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
	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// upstream is a DNS server for the tests, over UDP and TCP on one port of 127.0.0.1: files.corp.lan is 192.168.1.20,
// app.example.com is 203.0.113.10 on the internet
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
		addresses := map[string][4]byte{"files.corp.lan.": {192, 168, 1, 20}, "app.example.com.": {203, 0, 113, 10}}
		if address, ok := addresses[question.Name.String()]; ok {
			reply.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: address},
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
				if query, err := names.ReadMessage(conn); err == nil {
					names.WriteMessage(conn, answer(query))
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
// the addresses of their names open before the answer comes back, the stand-in addresses of the internet ones in it.
func TestResolver(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := network.NewFake()
	service, err := core.New(db, fake, core.Options{LoginPort: 8181, PublicHost: "vpn.example.com", Log: log,
		UpstreamPort: upstream(t), StandIns: netip.MustParsePrefix(core.DefaultStandIns)})
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
	access := []string{"*.corp.lan", "app.example.com"}
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
		if err := names.WriteMessage(stream, query(t, name)); err != nil {
			t.Fatal(err)
		}
		reply, err := names.ReadMessage(stream)
		if err != nil {
			t.Fatal(err)
		}
		read(reply)
	}
	if len(fake.Learned["wg0"]) != 1 {
		t.Errorf("TCP: %+v", fake.Learned)
	}
	// a name on the internet: its stand-in address in the answer, leading to it
	if err := names.WriteMessage(stream, query(t, "app.example.com.")); err != nil {
		t.Fatal(err)
	}
	reply, err := names.ReadMessage(stream)
	if err != nil {
		t.Fatal(err)
	}
	answers := read(reply)
	if len(answers) != 1 {
		t.Fatalf("internet name: %+v", answers)
	}
	standIn := netip.AddrFrom4(answers[0].Body.(*dnsmessage.AResource).A)
	if !netip.MustParsePrefix(core.DefaultStandIns).Contains(standIn) ||
		fake.ReachesThrough("wg0", address, standIn) != netip.MustParseAddr("203.0.113.10") {
		t.Errorf("internet name: %v, stand-ins %v", standIn, fake.StandIns)
	}
	// asked by the Authway app: the real address, and the route for the app
	var edns dnsmessage.ResourceHeader
	if err := edns.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	appQuery, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA,
			Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{Header: edns, Body: &dnsmessage.OPTResource{
			Options: []dnsmessage.Option{{Code: names.RoutesOption}}}}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := names.WriteMessage(stream, appQuery); err != nil {
		t.Fatal(err)
	}
	if reply, err = names.ReadMessage(stream); err != nil {
		t.Fatal(err)
	}
	answers = read(reply)
	routes := names.Routes(reply)
	if len(answers) != 1 || netip.AddrFrom4(answers[0].Body.(*dnsmessage.AResource).A) != netip.MustParseAddr("203.0.113.10") ||
		len(routes) != 1 || routes[0].Addr != netip.MustParseAddr("203.0.113.10") ||
		!fake.Reaches("wg0", address, netip.MustParseAddr("203.0.113.10")) {
		t.Errorf("asked by the app: %+v, routes %+v", answers, routes)
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
