package network

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Ports are what an access rule allows of the traffic to its address, network or name: some protocols, some of their
// ports. An administrator writes them after the address or the name: tcp/443, udp/53, tcp/8000-8090, tcp/80,443,
// icmp, or tcp alone for all of its ports. The zero value is all the traffic.
type Ports struct {
	// nil for none of the protocol, empty for all of its ports, else the ranges, sorted and apart
	TCP, UDP []PortRange
	ICMP     bool
}

// PortRange is a port, or the ports from From to To.
type PortRange struct {
	From, To uint16
}

// MaxPortItems is the most ports and ranges a rule can list: nftables keeps them in a set of the rule.
const MaxPortItems = 32

// ParsePorts reads the ports of a rule, the words after its address or name, in any case: tcp/443,80 udp/53 icmp. A
// protocol written twice gets the ports of both. false for anything else, and for no words.
func ParsePorts(words []string) (Ports, bool) {
	if len(words) == 0 {
		return Ports{}, false
	}
	var ports Ports
	items := 0
	for _, word := range words {
		protocol, list, hasList := strings.Cut(strings.ToLower(word), "/")
		if protocol == "icmp" {
			if hasList {
				return Ports{}, false
			}
			ports.ICMP = true
			continue
		}
		var target *[]PortRange
		switch protocol {
		case "tcp":
			target = &ports.TCP
		case "udp":
			target = &ports.UDP
		default:
			return Ports{}, false
		}
		if !hasList {
			// all of them
			*target = []PortRange{}
			continue
		}
		ranges, ok := parseRanges(list)
		items += len(ranges)
		if !ok || items > MaxPortItems {
			return Ports{}, false
		}
		// all of them already: they stay all
		if *target == nil || len(*target) > 0 {
			*target = append(*target, ranges...)
		}
	}
	ports.TCP, ports.UDP = merge(ports.TCP), merge(ports.UDP)
	return ports, true
}

// parseRanges reads 80,443,8000-8090
func parseRanges(text string) ([]PortRange, bool) {
	var ranges []PortRange
	for _, item := range strings.Split(text, ",") {
		from, to, isRange := strings.Cut(item, "-")
		first, ok1 := parsePort(from)
		last := first
		ok2 := true
		if isRange {
			last, ok2 = parsePort(to)
		}
		if !ok1 || !ok2 || last < first {
			return nil, false
		}
		ranges = append(ranges, PortRange{first, last})
	}
	return ranges, len(ranges) > 0
}

func parsePort(text string) (uint16, bool) {
	// digits only: no sign, no spaces
	if text == "" || len(text) > 5 || strings.Trim(text, "0123456789") != "" {
		return 0, false
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < 1 || value > 65535 {
		return 0, false
	}
	return uint16(value), true
}

// merge sorts ranges and joins those that overlap or touch: nftables refuses overlapping elements in a set. nil and
// empty stay as they are.
func merge(ranges []PortRange) []PortRange {
	if len(ranges) == 0 {
		return ranges
	}
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b PortRange) int { return int(a.From) - int(b.From) })
	merged := []PortRange{sorted[0]}
	for _, item := range sorted[1:] {
		last := &merged[len(merged)-1]
		if int(item.From) <= int(last.To)+1 {
			last.To = max(last.To, item.To)
			continue
		}
		merged = append(merged, item)
	}
	return merged
}

// All tells whether the ports are all the traffic: a rule without ports.
func (p Ports) All() bool {
	return p.TCP == nil && p.UDP == nil && !p.ICMP
}

// String writes the ports as ParsePorts reads them, the same way for the same ports: tcp/80,443 udp/53 icmp. "" for
// all the traffic.
func (p Ports) String() string {
	var words []string
	for _, protocol := range []struct {
		name   string
		ranges []PortRange
	}{{"tcp", p.TCP}, {"udp", p.UDP}} {
		switch {
		case protocol.ranges == nil:
		case len(protocol.ranges) == 0:
			words = append(words, protocol.name)
		default:
			words = append(words, protocol.name+"/"+rangesText(protocol.ranges, ","))
		}
	}
	if p.ICMP {
		words = append(words, "icmp")
	}
	return strings.Join(words, " ")
}

func rangesText(ranges []PortRange, separator string) string {
	texts := make([]string, 0, len(ranges))
	for _, item := range ranges {
		if item.From == item.To {
			texts = append(texts, strconv.Itoa(int(item.From)))
		} else {
			texts = append(texts, fmt.Sprintf("%d-%d", item.From, item.To))
		}
	}
	return strings.Join(texts, separator)
}

// matches are the matches of nftables of the traffic the ports allow, one for each rule: a packet passes when one of
// them matches. ICMPv6 for IPv6. None for all the traffic: the rule needs no match.
func (p Ports) matches(ipv6 bool) []string {
	var list []string
	for _, protocol := range []struct {
		name   string
		ranges []PortRange
	}{{"tcp", p.TCP}, {"udp", p.UDP}} {
		switch {
		case protocol.ranges == nil:
		case len(protocol.ranges) == 0:
			list = append(list, "meta l4proto "+protocol.name)
		case len(protocol.ranges) == 1 && protocol.ranges[0].From == protocol.ranges[0].To:
			list = append(list, fmt.Sprintf("%s dport %d", protocol.name, protocol.ranges[0].From))
		default:
			list = append(list, fmt.Sprintf("%s dport { %s }", protocol.name, rangesText(protocol.ranges, ", ")))
		}
	}
	if p.ICMP {
		if ipv6 {
			list = append(list, "meta l4proto ipv6-icmp")
		} else {
			list = append(list, "meta l4proto icmp")
		}
	}
	return list
}

// PortAccess is an access rule with ports: an address or a network, and what it allows of the traffic to it.
type PortAccess struct {
	Prefix netip.Prefix
	Ports  Ports
}

// LearnedPortsSet is the set of the addresses that the peers learned for the names of their rules with these ports,
// by the text of the ports, as LearnedSet has those of the rules without ports. The name holds a hash of the text: the
// commands that add an address between two Apply find the set the ruleset made.
func LearnedPortsSet(iface string, ipv6 bool, ports string) string {
	hash := fnv.New32a()
	hash.Write([]byte(ports))
	version := ""
	if ipv6 {
		version = "6"
	}
	return fmt.Sprintf("%s_lp%s_%08x", iface, version, hash.Sum32())
}
