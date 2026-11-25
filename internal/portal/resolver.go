package portal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/phatdo1819/authway-server/internal/names"
)

// The DNS server of the peers with names in their access rules: once they're logged in, nftables sends their DNS
// queries here, whatever server they ask. Each one goes to the DNS servers of their server, and before the answer goes
// back, Authway Server opens the addresses it gives for the names of their rules, and puts the stand-in addresses of
// their internet addresses in it, or for the Authway app, which routes them itself, the list of the routes: the
// device connects at once.

const (
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
				query, err := names.ReadMessage(conn)
				if err != nil || !p.resolverLimiter.allow(source, time.Now()) {
					return
				}
				reply := p.resolve(ctx, source, query, true)
				if reply == nil || names.WriteMessage(conn, reply) != nil {
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
	// the Authway app routes the addresses of the names itself: the DNS servers never see its option
	asked, routes := names.TakeRoutes(query)
	for _, upstream := range upstreams {
		reply, err := names.Exchange(ctx, upstream, asked, tcp)
		if err != nil {
			p.log.Debug("a DNS server didn't answer a query of a peer", "server", upstream, "error", err)
			continue
		}
		if routes {
			reply = names.WithoutRoutes(reply)
		}
		return p.core.Learn(source, reply, routes)
	}
	return names.Refused(query)
}
