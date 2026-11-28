package flows

import (
	"net/netip"
	"testing"
)

// The events of conntrack 1.4.8 -E -o xml,id, as the container prints them: a new connection, and its end with the
// bytes of both directions; a translated one; ICMP without ports; IPv6; and what isn't an event.
func TestParse(t *testing.T) {
	addr := netip.MustParseAddr
	newFlow := `<flow type="new"><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>10.8.0.2</src><dst>192.168.1.5</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>53428</sport><dport>3389</dport></layer4></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>192.168.1.5</src><dst>172.18.0.2</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>3389</sport><dport>53428</dport></layer4></meta><meta direction="independent"><state>SYN_SENT</state><timeout>120</timeout><id>1768309768</id><unreplied/></meta></flow>`
	event, ok := Parse([]byte(newFlow + "\n"))
	if !ok || !event.New || event.ID != 1768309768 || event.Protocol != 6 || event.Source != addr("10.8.0.2") ||
		event.Destination != addr("192.168.1.5") || event.Port != 3389 || event.ReplySource != addr("192.168.1.5") {
		t.Fatalf("new: %+v %v", event, ok)
	}
	destroy := `<flow type="destroy"><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>10.8.0.2</src><dst>198.18.0.7</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>53428</sport><dport>443</dport></layer4><counters><packets>7</packets><bytes>471</bytes></counters></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>203.0.113.10</src><dst>172.18.0.2</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>443</sport><dport>53428</dport></layer4><counters><packets>6</packets><bytes>8210</bytes></counters></meta><meta direction="independent"><id>99</id></meta></flow>`
	event, ok = Parse([]byte(destroy))
	if !ok || event.New || event.ID != 99 || event.Destination != addr("198.18.0.7") || event.ReplySource != addr("203.0.113.10") ||
		event.Sent != 471 || event.Received != 8210 {
		t.Fatalf("destroy: %+v %v", event, ok)
	}
	icmp := `<flow type="new"><meta direction="original"><layer3 protonum="10" protoname="ipv6"><src>fd00:1::2</src><dst>fd00:5::5</dst></layer3><layer4 protonum="58" protoname="ipv6-icmp"><type>128</type><code>0</code><id>7</id></layer4></meta><meta direction="reply"><layer3 protonum="10" protoname="ipv6"><src>fd00:5::5</src><dst>fd00:1::2</dst></layer3><layer4 protonum="58" protoname="ipv6-icmp"><type>129</type><code>0</code><id>7</id></layer4></meta><meta direction="independent"><id>5</id></meta></flow>`
	event, ok = Parse([]byte(icmp))
	if !ok || event.Protocol != 58 || event.Port != 0 || event.Destination != addr("fd00:5::5") {
		t.Fatalf("ICMPv6: %+v %v", event, ok)
	}
	for _, line := range []string{
		`<?xml version="1.0" encoding="utf-8"?>`, `<conntrack>`, `</conntrack>`, "",
		`<flow type="update"><meta direction="original"><layer3><src>10.8.0.2</src><dst>192.168.1.5</dst></layer3></meta><meta direction="reply"><layer3><src>192.168.1.5</src><dst>10.8.0.2</dst></layer3></meta></flow>`,
		`<flow type="new"><meta direction="original"><layer3><src>nonsense</src><dst>192.168.1.5</dst></layer3></meta></flow>`,
		`<flow type="new"><meta direction="original"><layer3><src>10.8.0.2</src><dst>192.168.1.5</dst></layer3></meta></flow>`,
		`<flow type="new"><meta`,
	} {
		if event, ok := Parse([]byte(line)); ok {
			t.Errorf("%q: read as %+v", line, event)
		}
	}
}
