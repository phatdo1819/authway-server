package portal

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/phatdo1819/authway-server/internal/peerconf"
)

// Before the login, nftables redirects the web requests and the DNS queries of the peers of the servers with
// Redirect here: every name resolves to the address of the server, and every web request gets a redirect to the
// login page, so any plain http:// address opens it. Nothing is forwarded: DNS can't carry data out.

// DNSTTL is short: after the login, the real names must work at once.
const DNSTTL = 1

// RedirectHandler answers the redirected web requests with the address of the login page: the IPv4 one, as in the
// configuration files, also for a request that came over IPv6.
func (p *Portal) RedirectHandler() http.Handler {
	return headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, _ := p.client(r)
		server, _, ok := p.core.RedirectTarget(address)
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, peerconf.LoginURL(server, p.core.LoginPort()), http.StatusFound)
	}))
}

// ServeDNS answers the redirected DNS queries on address until ctx ends. Only the peers of the servers with Redirect
// get an answer.
func (p *Portal) ServeDNS(ctx context.Context, address string) error {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buffer := make([]byte, 512)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.log.Warn("DNS answer failed", "error", err)
			continue
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		source, ok := netip.AddrFromSlice(udp.IP)
		if !ok {
			continue
		}
		source = source.Unmap()
		if p.devPeer.IsValid() && source.IsLoopback() {
			source = p.devPeer
		}
		server, server6, ok := p.core.RedirectTarget(source)
		if !ok {
			continue
		}
		if reply := DNSAnswer(buffer[:n], server, server6); reply != nil {
			conn.WriteTo(reply, from)
		}
	}
}

// DNSAnswer answers a standard query of one question: an A record with the IPv4 address for the A queries, an AAAA
// record with the IPv6 one for the AAAA queries when the server has one, no record for the other types. It returns
// nil for anything else, which gets no answer.
func DNSAnswer(query []byte, address, address6 netip.Addr) []byte {
	if len(query) < 12 || !address.Is4() {
		return nil
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	// a response, or not a standard query, or not one question
	if flags&0x8000 != 0 || (flags>>11)&0xF != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	offset, nameLength := 12, 0
	for {
		if offset >= len(query) {
			return nil
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		// a question has no compressed names
		if length > 63 {
			return nil
		}
		nameLength += length + 1
		if nameLength > 255 {
			return nil
		}
		offset += length
	}
	if offset+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	qclass := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	question := query[12 : offset+4]

	reply := make([]byte, 12, 12+len(question)+28)
	copy(reply[0:2], query[0:2])
	// response, authoritative, recursion desired as asked, recursion available
	binary.BigEndian.PutUint16(reply[2:4], 0x8000|0x0400|(flags&0x0100)|0x0080)
	binary.BigEndian.PutUint16(reply[4:6], 1)
	reply = append(reply, question...)
	switch {
	case qtype == 1 && qclass == 1:
		binary.BigEndian.PutUint16(reply[6:8], 1)
		// the name of the question, type A, class IN, the TTL, 4 bytes of data
		record := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, DNSTTL, 0, 4}
		ip := address.As4()
		reply = append(reply, record...)
		reply = append(reply, ip[:]...)
	case qtype == 28 && qclass == 1 && address6.Is6() && !address6.Is4In6():
		binary.BigEndian.PutUint16(reply[6:8], 1)
		// type AAAA, 16 bytes of data
		record := []byte{0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, DNSTTL, 0, 16}
		ip := address6.As16()
		reply = append(reply, record...)
		reply = append(reply, ip[:]...)
	}
	return reply
}
