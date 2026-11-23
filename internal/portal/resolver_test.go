package portal

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// upstream is a DNS server for the tests, over UDP and TCP on one port of 127.0.0.1: files.corp.lan is 192.168.1.20
func upstream(t *testing.T) int {
	t.Helper()
	var packets net.PacketConn
	var listener net.Listener
	for range 20 {
		var err error
		if listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if packets, err = net.ListenPacket("udp", listener.Addr().String()); err == nil {
			break
		}
		listener.Close()
	}
	if packets == nil {
		t.Fatal("no port for both UDP and TCP")
	}
	t.Cleanup(func() { packets.Close(); listener.Close() })
	answer := func(query []byte) []byte {
		var parser dnsmessage.Parser
		header, err := parser.Start(query)
		if err != nil {
			return nil
		}
		question, err := parser.Question()
		if err != nil {
			return nil
		}
		reply := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true}, Questions: []dnsmessage.Question{question}}
		if question.Name.String() == "files.corp.lan." {
			reply.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 20}},
			}}
		}
		data, _ := reply.Pack()
		return data
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets.WriteTo(answer(buffer[:n]), from)
		}
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if query, err := readMessage(conn); err == nil {
					writeMessage(conn, answer(query))
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func query(t *testing.T, name string) []byte {
	t.Helper()
	data, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The DNS server of the peers with names: their queries go to the DNS servers of their server, over UDP and TCP, and
// the addresses of their names open before the answer comes back.
func TestResolver(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := network.NewFake()
	service, err := core.New(db, fake, core.Options{LoginPort: 8181, PublicHost: "vpn.example.com", Log: log,
		UpstreamPort: upstream(t)})
	if err != nil {
		t.Fatal(err)
	}
	suggestion, _ := service.ServerDefaults(0)
	input := suggestion.ServerInput
	input.Name, input.AuthMode = "Office", store.AuthKey
	input.Networks, input.DNS = []string{"192.168.1.0/24"}, []string{"127.0.0.1"}
	server, err := service.CreateServer(core.Actor{Username: "tester"}, input)
	if err != nil {
		t.Fatal(err)
	}
	access := []string{"*.corp.lan"}
	peer, err := service.CreatePeer(core.Actor{Username: "tester"}, server.ID, core.PeerInput{Name: "kiosk", Enabled: true, Access: &access})
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(peer.Address)
	// the queries from this computer are the ones of the peer
	pages := New(service, Options{Log: log, DevPeer: address})
	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pages.serveResolver(ctx, packets, listener)

	files := netip.MustParseAddr("192.168.1.20")
	read := func(reply []byte) []dnsmessage.Resource {
		t.Helper()
		var message dnsmessage.Message
		if err := message.Unpack(reply); err != nil || message.ID != 4242 || !message.Response {
			t.Fatalf("reply: %+v %v", message.Header, err)
		}
		return message.Answers
	}

	// UDP
	conn, err := net.Dial("udp", packets.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query(t, "files.corp.lan.")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if answers := read(buffer[:n]); len(answers) != 1 || !fake.Reaches("wg0", address, files) {
		t.Fatalf("UDP: %+v, learned %+v", answers, fake.Learned)
	}

	// TCP, another name of the server: answered, nothing learned
	stream, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	for _, name := range []string{"files.corp.lan.", "www.example.com."} {
		if err := writeMessage(stream, query(t, name)); err != nil {
			t.Fatal(err)
		}
		reply, err := readMessage(stream)
		if err != nil {
			t.Fatal(err)
		}
		read(reply)
	}
	if len(fake.Learned["wg0"]) != 1 {
		t.Errorf("TCP: %+v", fake.Learned)
	}
	// a reply sent to it isn't a query
	if reply := pages.resolve(ctx, address, sentReply(t), false); reply != nil {
		t.Errorf("a reply answered: %x", reply)
	}
}

// sentReply is a reply, as a peer could send one
func sentReply(t *testing.T) []byte {
	data := query(t, "files.corp.lan.")
	data[2] |= 0x80
	return data
}
