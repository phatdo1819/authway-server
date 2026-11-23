package portal

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/phatdo1819/authway-server/internal/names"
)

// The DNS server of the peers with names in their access rules: once they're logged in, nftables sends their DNS
// queries here, whatever server they ask. Each one goes to the DNS servers of their server, and before the answer goes
// back, Authway Server opens the addresses it gives for the names of their rules: the device connects at once.

const (
	// how long a DNS server has to answer, before the next one is asked
	resolverTimeout = 3 * time.Second
	// the queries answered at once: past it, a query is dropped and the device asks again
	maxResolving = 256
	// a TCP connection: the time for each query, and the queries it can send
	resolverTCPTimeout = 10 * time.Second
	maxTCPQueries      = 100
)

// ServeResolver answers on address, over UDP and TCP, until ctx ends.
func (p *Portal) ServeResolver(ctx context.Context, address string) error {
	packets, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		packets.Close()
		return err
	}
	p.serveResolver(ctx, packets, listener)
	return nil
}

func (p *Portal) serveResolver(ctx context.Context, packets net.PacketConn, listener net.Listener) {
	go func() {
		<-ctx.Done()
		packets.Close()
		listener.Close()
	}()
	slots := make(chan struct{}, maxResolving)
	go p.resolveTCP(ctx, listener, slots)
	buffer := make([]byte, 65535)
	for {
		n, from, err := packets.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			p.log.Warn("DNS query of a peer failed", "error", err)
			continue
		}
		source, ok := p.source(from)
		if !ok || !p.resolverLimiter.allow(source, time.Now()) {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		query := append([]byte(nil), buffer[:n]...)
		go func() {
			defer func() { <-slots }()
			if reply := p.resolve(ctx, source, query, false); reply != nil {
				packets.WriteTo(reply, from)
			}
		}()
	}
}

func (p *Portal) resolveTCP(ctx context.Context, listener net.Listener, slots chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		source, ok := p.source(conn.RemoteAddr())
		if !ok {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer conn.Close()
			for count := 0; count < maxTCPQueries; count++ {
				conn.SetDeadline(time.Now().Add(resolverTCPTimeout))
				query, err := readMessage(conn)
				if err != nil || !p.resolverLimiter.allow(source, time.Now()) {
					return
				}
				reply := p.resolve(ctx, source, query, true)
				if reply == nil || writeMessage(conn, reply) != nil {
					return
				}
			}
		}()
	}
}

// source is the tunnel address of a query: on the fake network, the one of the peer of this computer
func (p *Portal) source(from net.Addr) (netip.Addr, bool) {
	var address netip.Addr
	switch from := from.(type) {
	case *net.UDPAddr:
		address, _ = netip.AddrFromSlice(from.IP)
	case *net.TCPAddr:
		address, _ = netip.AddrFromSlice(from.IP)
	}
	address = address.Unmap()
	if p.devPeer.IsValid() && address.IsLoopback() {
		address = p.devPeer
	}
	return address, address.IsValid()
}

// resolve asks the DNS servers of the peer in turn, and learns from the first answer; when none answers, the device
// is told so at once. nil for what isn't a query of a peer with names.
func (p *Portal) resolve(ctx context.Context, source netip.Addr, query []byte, tcp bool) []byte {
	if len(query) < 12 || query[2]&0x80 != 0 {
		return nil
	}
	upstreams, ok := p.core.Resolver(source)
	if !ok {
		return nil
	}
	for _, upstream := range upstreams {
		reply, err := exchange(ctx, upstream, query, tcp)
		if err != nil {
			p.log.Debug("a DNS server didn't answer a query of a peer", "server", upstream, "error", err)
			continue
		}
		p.core.Learn(source, reply)
		return reply
	}
	return names.Refused(query)
}

// exchange sends a query to a DNS server and reads its reply, over UDP or TCP
func exchange(ctx context.Context, server netip.AddrPort, query []byte, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	dialer := net.Dialer{Timeout: resolverTimeout}
	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(resolverTimeout))
	if tcp {
		if err := writeMessage(conn, query); err != nil {
			return nil, err
		}
		reply, err := readMessage(conn)
		if err != nil {
			return nil, err
		}
		if !replies(reply, query) {
			return nil, errors.New("not the reply to the query")
		}
		return reply, nil
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	for {
		// another packet on the port: ignored, until the reply or the deadline
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		if replies(buffer[:n], query) {
			return append([]byte(nil), buffer[:n]...), nil
		}
	}
}

// replies tells whether a message is a reply with the ID of a query
func replies(reply, query []byte) bool {
	return len(reply) >= 12 && reply[2]&0x80 != 0 && reply[0] == query[0] && reply[1] == query[1]
}

// readMessage reads a DNS message of a TCP connection: its length on 2 bytes, then the message
func readMessage(conn io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, message); err != nil {
		return nil, err
	}
	return message, nil
}

func writeMessage(conn io.Writer, message []byte) error {
	if len(message) > 65535 {
		return errors.New("a DNS message is 65535 bytes at most")
	}
	data := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(data, uint16(len(message)))
	copy(data[2:], message)
	_, err := conn.Write(data)
	return err
}
