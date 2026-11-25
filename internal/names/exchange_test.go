package names

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Query and Looked: the query of Authway Server for a name, and what the reply says of it.
func TestQueryAndLooked(t *testing.T) {
	data, err := Query(42, "Files.Corp.LAN.", true)
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(data); err != nil {
		t.Fatal(err)
	}
	if message.Header.ID != 42 || message.Header.Response || !message.Header.RecursionDesired || len(message.Questions) != 1 ||
		message.Questions[0].Name.String() != "files.corp.lan." || message.Questions[0].Type != dnsmessage.TypeAAAA ||
		len(message.Additionals) != 1 || message.Additionals[0].Header.Type != dnsmessage.TypeOPT || message.Additionals[0].Header.Class != 1232 {
		t.Errorf("query: %+v", message)
	}
	data4, err := Query(7, "files.corp.lan", false)
	var parsed dnsmessage.Message
	if err != nil || parsed.Unpack(data4) != nil || len(parsed.Questions) != 1 || parsed.Questions[0].Type != dnsmessage.TypeA {
		t.Errorf("IPv4 query: %+v %v", parsed, err)
	}

	// the addresses, through the aliases; none for a name that doesn't exist; false for a failure or another name
	addresses, ok := Looked(reply(t, "files.corp.lan.", dnsmessage.RCodeSuccess, cname("files.corp.lan.", 3600, "nas.corp.lan."),
		a("nas.corp.lan.", 60, "192.168.1.20")), "FILES.corp.lan")
	if !ok || !slices.Equal(addresses, []Address{{netip.MustParseAddr("192.168.1.20"), 60 * time.Second}}) {
		t.Errorf("addresses: %+v %v", addresses, ok)
	}
	if addresses, ok := Looked(reply(t, "files.corp.lan.", dnsmessage.RCodeNameError), "files.corp.lan"); !ok || len(addresses) != 0 {
		t.Errorf("NXDOMAIN: %+v %v", addresses, ok)
	}
	if addresses, ok := Looked(reply(t, "files.corp.lan.", dnsmessage.RCodeSuccess), "files.corp.lan"); !ok || len(addresses) != 0 {
		t.Errorf("no address: %+v %v", addresses, ok)
	}
	for name, bad := range map[string][]byte{
		"SERVFAIL":     reply(t, "files.corp.lan.", dnsmessage.RCodeServerFailure),
		"REFUSED":      reply(t, "files.corp.lan.", dnsmessage.RCodeRefused),
		"another name": reply(t, "other.corp.lan.", dnsmessage.RCodeSuccess, a("other.corp.lan.", 60, "192.168.1.9")),
		"a query":      data,
		"garbage":      []byte("hello"),
	} {
		if addresses, ok := Looked(bad, "files.corp.lan"); ok {
			t.Errorf("%s read: %+v", name, addresses)
		}
	}
}

// Ask: over UDP, and again over TCP when the reply was cut.
func TestAsk(t *testing.T) {
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
	// big.corp.lan doesn't fit in UDP: the reply over UDP is cut, without its answers
	answer := func(query []byte, tcp bool) []byte {
		var message dnsmessage.Message
		if err := message.Unpack(query); err != nil {
			return nil
		}
		name := message.Questions[0].Name.String()
		out := dnsmessage.Message{Header: dnsmessage.Header{ID: message.Header.ID, Response: true}, Questions: message.Questions}
		if name == "big.corp.lan." && !tcp {
			out.Header.Truncated = true
		} else {
			out.Answers = []dnsmessage.Resource{a(name, 60, map[bool]string{true: "192.168.1.30", false: "192.168.1.20"}[tcp])}
		}
		data, _ := out.Pack()
		return data
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets.WriteTo(answer(buffer[:n], false), from)
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
				if query, err := ReadMessage(conn); err == nil {
					WriteMessage(conn, answer(query, true))
				}
			}()
		}
	}()
	server := netip.MustParseAddrPort(listener.Addr().String())
	for name, want := range map[string]string{"files.corp.lan": "192.168.1.20", "big.corp.lan": "192.168.1.30"} {
		query, err := Query(9, name, false)
		if err != nil {
			t.Fatal(err)
		}
		data, err := Ask(context.Background(), server, query)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if addresses, ok := Looked(data, name); !ok || len(addresses) != 1 || addresses[0].Addr != netip.MustParseAddr(want) {
			t.Errorf("%s: %+v %v", name, addresses, ok)
		}
	}
	// a server that doesn't answer: an error once the time is up
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	query, _ := Query(9, "files.corp.lan", false)
	start := time.Now()
	if _, err := Ask(ctx, netip.MustParseAddrPort(silent.LocalAddr().String()), query); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("silent server: %v after %v", err, time.Since(start))
	}
}
