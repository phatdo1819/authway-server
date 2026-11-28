// Package flows reads the connections of the peers from the connection tracking of the kernel, for the flow logs:
// each new connection, and each one that ends with its bytes. It runs `conntrack -E` with XML output, one event a
// line, in the network of the container: only the traffic of Authway Server and of its tunnels.
package flows

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Event is a connection that starts, or ends with its bytes.
type Event struct {
	New bool
	// the ID of the connection in the kernel: the same in its start and its end
	ID uint32
	// the protocol: 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6...
	Protocol uint8
	// the original direction: from the peer
	Source      netip.Addr
	Destination netip.Addr
	// 0 without ports
	Port uint16
	// where the answers come from: the real destination when the firewall translated it, a stand-in address say
	ReplySource netip.Addr
	// at the end, with the accounting of the kernel on: the bytes from the source, and the bytes back to it
	Sent, Received uint64
}

type xmlFlow struct {
	Type  string    `xml:"type,attr"`
	Metas []xmlMeta `xml:"meta"`
}

type xmlMeta struct {
	Direction string     `xml:"direction,attr"`
	Layer3    xmlLayer3  `xml:"layer3"`
	Layer4    xmlLayer4  `xml:"layer4"`
	Counters  xmlCounter `xml:"counters"`
	ID        uint32     `xml:"id"`
}

type xmlLayer3 struct {
	Source      string `xml:"src"`
	Destination string `xml:"dst"`
}

type xmlLayer4 struct {
	Protocol uint8  `xml:"protonum,attr"`
	Port     uint16 `xml:"dport"`
}

type xmlCounter struct {
	Bytes uint64 `xml:"bytes"`
}

// Parse reads an event of `conntrack -E -o xml,id`: one <flow> line. false for the other lines (the XML declaration,
// <conntrack>), the other events, and a flow it can't read.
func Parse(line []byte) (Event, bool) {
	line = bytes.TrimSpace(line)
	if !bytes.HasPrefix(line, []byte("<flow ")) {
		return Event{}, false
	}
	var flow xmlFlow
	if err := xml.Unmarshal(line, &flow); err != nil {
		return Event{}, false
	}
	var event Event
	switch flow.Type {
	case "new":
		event.New = true
	case "destroy":
	default:
		return Event{}, false
	}
	found := 0
	for _, meta := range flow.Metas {
		switch meta.Direction {
		case "original":
			source, err1 := netip.ParseAddr(meta.Layer3.Source)
			destination, err2 := netip.ParseAddr(meta.Layer3.Destination)
			if err1 != nil || err2 != nil {
				return Event{}, false
			}
			event.Source, event.Destination = source.Unmap(), destination.Unmap()
			event.Protocol, event.Port = meta.Layer4.Protocol, meta.Layer4.Port
			event.Sent = meta.Counters.Bytes
			found++
		case "reply":
			source, err := netip.ParseAddr(meta.Layer3.Source)
			if err != nil {
				return Event{}, false
			}
			event.ReplySource = source.Unmap()
			event.Received = meta.Counters.Bytes
			found++
		case "independent":
			event.ID = meta.ID
		}
	}
	if found != 2 {
		return Event{}, false
	}
	return event, true
}

// BufferSize is the receive buffer of the netlink socket of conntrack: the events of a busy minute wait there while
// Authway Server reads them. Past it, the kernel drops events, and conntrack says so.
const BufferSize = 8 << 20

// Watch runs conntrack until ctx ends or it stops, and gives each event to each. lost is called when conntrack says
// that the kernel dropped events. An error when conntrack can't run or stops by itself.
func Watch(ctx context.Context, each func(Event), lost func()) error {
	path, err := exec.LookPath("conntrack")
	if err != nil {
		return errors.New("conntrack isn't installed")
	}
	command := exec.CommandContext(ctx, path, "-E", "-e", "NEW,DESTROY", "-o", "xml,id", "-b", fmt.Sprint(BufferSize))
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	// the warnings of conntrack: ENOBUFS, events lost; the last line says why it stopped
	last := make(chan string, 1)
	go func() {
		var line string
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line = scanner.Text()
			if strings.Contains(line, "ENOBUFS") || strings.Contains(strings.ToLower(line), "losing events") {
				lost()
			}
		}
		last <- line
	}()
	reader := bufio.NewReaderSize(stdout, 64<<10)
	for {
		line, err := reader.ReadBytes('\n')
		if event, ok := Parse(line); ok {
			each(event)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_ = command.Process.Kill()
			}
			break
		}
	}
	waitErr := command.Wait()
	message := <-last
	if ctx.Err() != nil {
		return nil
	}
	if message == "" && waitErr != nil {
		message = waitErr.Error()
	}
	if message == "" {
		message = "it stopped"
	}
	return fmt.Errorf("conntrack: %s", message)
}

// Accounting tells whether the kernel counts the bytes of each connection, for the ends of the connections:
// net.netfilter.nf_conntrack_acct, false when it can't be read.
func Accounting() bool {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	return err == nil && strings.TrimSpace(string(data)) == "1"
}

// Interval is how often the flows are written: the rows of a minute together, in one transaction.
const Interval = time.Minute
