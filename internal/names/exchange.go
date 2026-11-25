package names

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// How Authway Server talks to the DNS servers: for the queries of the peers it sends on, and for the names it looks up
// itself.

// ExchangeTimeout is how long a DNS server has to answer, before the next one is asked.
const ExchangeTimeout = 3 * time.Second

// Exchange sends a query to a DNS server and reads its reply, over UDP or TCP.
func Exchange(ctx context.Context, server netip.AddrPort, query []byte, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	dialer := net.Dialer{Timeout: ExchangeTimeout}
	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(ExchangeTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	conn.SetDeadline(deadline)
	if tcp {
		if err := WriteMessage(conn, query); err != nil {
			return nil, err
		}
		reply, err := ReadMessage(conn)
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

// Ask sends a query to a DNS server over UDP, and again over TCP when the reply didn't fit: how Authway Server looks
// names up itself.
func Ask(ctx context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
	reply, err := Exchange(ctx, server, query, false)
	if err == nil && reply[2]&0x02 != 0 {
		return Exchange(ctx, server, query, true)
	}
	return reply, err
}

// replies tells whether a message is a reply with the ID of a query
func replies(reply, query []byte) bool {
	return len(reply) >= 12 && len(query) >= 2 && reply[2]&0x80 != 0 && reply[0] == query[0] && reply[1] == query[1]
}

// ReadMessage reads a DNS message of a TCP connection: its length on 2 bytes, then the message.
func ReadMessage(conn io.Reader) ([]byte, error) {
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

// WriteMessage writes a DNS message on a TCP connection, after its length.
func WriteMessage(conn io.Writer, message []byte) error {
	if len(message) > 65535 {
		return errors.New("a DNS message is 65535 bytes at most")
	}
	data := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(data, uint16(len(message)))
	copy(data[2:], message)
	_, err := conn.Write(data)
	return err
}

// Query is a query of Authway Server for the A records of a name, or for its AAAA records with ipv6: recursive, with
// EDNS for replies up to 1232 bytes over UDP.
func Query(id uint16, name string, ipv6 bool) ([]byte, error) {
	asked, err := dnsmessage.NewName(normal(name) + ".")
	if err != nil {
		return nil, err
	}
	kind := dnsmessage.TypeA
	if ipv6 {
		kind = dnsmessage.TypeAAAA
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	message := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions:   []dnsmessage.Question{{Name: asked, Type: kind, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}},
	}
	return message.Pack()
}

// Looked reads the reply to a Query for a name: its addresses, through the aliases of the answer, none when the name
// doesn't exist or has none of the type asked. false when the DNS server couldn't answer (SERVFAIL, REFUSED...), or
// the reply isn't one for that name.
func Looked(reply []byte, name string) ([]Address, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(reply)
	if err != nil || !header.Response {
		return nil, false
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || normal(questions[0].Name.String()) != normal(name) {
		return nil, false
	}
	switch header.RCode {
	case dnsmessage.RCodeNameError:
		return nil, true
	case dnsmessage.RCodeSuccess:
		_, addresses, ok := Answer(reply)
		return addresses, ok
	}
	return nil, false
}
