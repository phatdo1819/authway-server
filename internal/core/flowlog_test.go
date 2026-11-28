package core

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/flows"
	"github.com/phatdo1819/authway-server/internal/store"
)

func flowEvent(id uint32, protocol uint8, source, destination string, port uint16) flows.Event {
	return flows.Event{New: true, ID: id, Protocol: protocol, Source: netip.MustParseAddr(source),
		Destination: netip.MustParseAddr(destination), Port: port, ReplySource: netip.MustParseAddr(destination)}
}

func (f *fixture) flowRows() []FlowView {
	f.t.Helper()
	page, err := f.s.FlowsPage(store.Filter{Limit: 100})
	if err != nil {
		f.t.Fatal(err)
	}
	return page.Items
}

// The flow logs: off until an administrator turns them on; the connections of the peers to the networks of their
// server, the other peers and their names add up by hour, peer, protocol, destination and port, with the bytes of
// their ends; never the traffic to Authway Server itself; the internet only with all the traffic. Written together,
// added to the rows of the same hour, pruned by days and by rows.
func TestFlowLogs(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	office := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24"}
		input.DNS = []string{"192.168.1.1"}
	})
	alice := f.user("alice")
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "alice laptop", Enabled: true, UserID: alice.ID,
		Access: access("192.168.1.0/24", "*.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "printer", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	record := func(events ...flows.Event) {
		for _, event := range events {
			f.s.flows.record(event, f.clock.Now())
		}
	}

	// off by default: nothing
	settings, err := f.s.Settings()
	if err != nil || settings.FlowLogs != FlowsOff || settings.FlowDays != DefaultFlowDays {
		t.Fatalf("settings: %+v %v", settings, err)
	}
	record(flowEvent(1, 6, peer.Address, "192.168.1.5", 3389))
	f.s.writeFlows()
	if rows := f.flowRows(); len(rows) != 0 {
		t.Fatalf("off: %+v", rows)
	}

	// the name of an internet address, from the answer of the peer's DNS: before the flow logs are on, as the device
	// keeps it
	address := netip.MustParseAddr(peer.Address)
	records := replyRecords(t, f.s.learn(address, answer(t, "app.example.com.", "A 203.0.113.10 600")))
	standIn := strings.TrimPrefix(records[0], "A ")

	bad := "everything"
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &bad}); fields(t, err)["flow_logs"] != "invalid" {
		t.Fatalf("a wrong mode: %v", err)
	}
	internal, days := FlowsInternal, 0
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &internal, FlowDays: &days}); fields(t, err)["flow_days"] != "invalid" {
		t.Fatalf("0 days: %v", err)
	}
	days = 30
	if settings, err = f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &internal, FlowDays: &days}); err != nil ||
		settings.FlowLogs != FlowsInternal || settings.FlowDays != 30 {
		t.Fatalf("on: %+v %v", settings, err)
	}
	if e := f.lastEvent("settings_changed"); !strings.Contains(e.Detail, "flow logs on, internal traffic, flow logs kept 30 days, was 90") {
		t.Errorf("event: %+v", e)
	}

	hour := f.clock.Now().Truncate(time.Hour).Unix()
	toStandIn := flowEvent(6, 6, peer.Address, standIn, 443)
	toStandIn.ReplySource = netip.MustParseAddr("203.0.113.10")
	redirected := flowEvent(8, 17, peer.Address, "192.168.1.1", 53)
	redirected.ReplySource = netip.MustParseAddr("10.8.0.1")
	record(
		// remote desktop twice, a printer's page, the other peer
		flowEvent(1, 6, peer.Address, "192.168.1.5", 3389),
		flowEvent(2, 6, peer.Address, "192.168.1.5", 3389),
		flowEvent(3, 17, peer.Address, "192.168.1.1", 53),
		flowEvent(4, 1, peer.Address, other.Address, 0),
		// the internet: not internal
		flowEvent(5, 6, peer.Address, "1.1.1.1", 443),
		// a stand-in address: the internet address of a name, with its name
		toStandIn,
		// Authway Server: its login page, a DNS query redirected to it
		flowEvent(7, 6, peer.Address, "10.8.0.1", 8181),
		redirected,
		// not a peer: the container itself
		flowEvent(9, 6, "172.18.0.2", "192.168.1.5", 389),
	)
	// the end of the first one, with its bytes
	end := flowEvent(1, 6, peer.Address, "192.168.1.5", 3389)
	end.New, end.Sent, end.Received = false, 1500, 64000
	record(end)
	f.s.writeFlows()
	rows := f.flowRows()
	byDestination := map[string]FlowView{}
	for _, row := range rows {
		byDestination[row.Protocol+" "+row.Address] = row
	}
	if len(rows) != 4 {
		t.Fatalf("rows: %+v", rows)
	}
	rdp := byDestination["tcp 192.168.1.5"]
	if rdp.Connections != 2 || rdp.Port != 3389 || rdp.Sent != 1500 || rdp.Received != 64000 || rdp.Hour != hour ||
		rdp.Username != "alice" || rdp.PeerName != "alice laptop" || rdp.ServerName != office.Name {
		t.Errorf("remote desktop: %+v", rdp)
	}
	if row := byDestination["icmp "+other.Address]; row.Connections != 1 || row.Port != 0 {
		t.Errorf("the other peer: %+v", row)
	}
	if row := byDestination["tcp 203.0.113.10"]; row.Name != "app.example.com" || row.Port != 443 {
		t.Errorf("the name of the stand-in: %+v", row)
	}
	if row := byDestination["udp 192.168.1.1"]; row.Connections != 1 {
		t.Errorf("DNS: %+v", row)
	}

	// a minute later, the end of the second one and a new one: added to the rows of the hour
	f.clock.advance(time.Minute)
	end.ID, end.Sent, end.Received = 2, 500, 1000
	record(end, flowEvent(10, 6, peer.Address, "192.168.1.5", 3389))
	f.s.writeFlows()
	rows = f.flowRows()
	if len(rows) != 4 || rows[0].Address != "192.168.1.5" || rows[0].Connections != 3 || rows[0].Sent != 2000 ||
		rows[0].LastAt != f.clock.Now().Unix() {
		t.Fatalf("added up: %+v", rows)
	}

	// all the traffic: the internet too; a connection that started before ends counted
	all := FlowsAll
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &all}); err != nil {
		t.Fatal(err)
	}
	late := flowEvent(11, 17, peer.Address, "9.9.9.9", 853)
	late.New, late.Sent = false, 77
	record(flowEvent(12, 6, peer.Address, "1.1.1.1", 443), late)
	f.s.writeFlows()
	page, err := f.s.FlowsPage(store.Filter{Search: "853", Limit: 10})
	if err != nil || page.Total != 1 || page.Items[0].Connections != 1 || page.Items[0].Sent != 77 {
		t.Fatalf("a connection of before: %+v %v", page, err)
	}
	if page, _ := f.s.FlowsPage(store.Filter{Search: "1.1.1.1", Limit: 10}); page.Total != 1 {
		t.Errorf("the internet with all: %+v", page)
	}

	// the status
	status, err := f.s.FlowStatus()
	if err != nil || status.Mode != FlowsAll || status.Days != 30 || status.Rows != 6 || status.Oldest != hour ||
		status.MaxRows != MaxFlowRows || status.Recording {
		t.Fatalf("status: %+v %v", status, err)
	}

	// pruned by days, and by rows: the oldest hours first
	f.clock.advance(2 * time.Hour)
	record(flowEvent(13, 6, peer.Address, "192.168.1.6", 22))
	f.s.writeFlows()
	if err := f.db.Q().PruneFlows(0, 1); err != nil {
		t.Fatal(err)
	}
	if rows := f.flowRows(); len(rows) != 1 || rows[0].Address != "192.168.1.6" {
		t.Fatalf("by rows: %+v", rows)
	}
	if err := f.db.Q().PruneFlows(f.clock.Now().Add(time.Second).Unix(), MaxFlowRows); err != nil {
		t.Fatal(err)
	}
	if rows := f.flowRows(); len(rows) != 0 {
		t.Fatalf("by days: %+v", rows)
	}

	// off again: what waits goes
	off := FlowsOff
	record(flowEvent(14, 6, peer.Address, "192.168.1.7", 22))
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &off}); err != nil {
		t.Fatal(err)
	}
	f.s.writeFlows()
	if rows := f.flowRows(); len(rows) != 0 {
		t.Fatalf("off: %+v", rows)
	}
}

// conntrack runs while the flow logs are on: its events are recorded, its losses counted, and the rows are written
// when it stops.
func TestFlowLogsWatch(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.serverWith(store.AuthKey, func(input *ServerInput) { input.Networks = []string{"192.168.1.0/24"} })
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 4)
	f.s.opts.Flows = func(ctx context.Context, each func(flows.Event), lost func()) error {
		each(flowEvent(1, 6, peer.Address, "192.168.1.5", 445))
		lost()
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}
	f.s.opts.FlowBytes = func() bool { return true }
	internal := FlowsInternal
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{FlowLogs: &internal}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		f.s.runFlows(ctx)
		close(stopped)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("conntrack didn't start")
	}
	status, err := f.s.FlowStatus()
	if err != nil || !status.Recording || status.Lost != 1 || !status.Bytes {
		t.Fatalf("status: %+v %v", status, err)
	}
	cancel()
	<-stopped
	if rows := f.flowRows(); len(rows) != 1 || rows[0].Port != 445 {
		t.Fatalf("written at the stop: %+v", rows)
	}
}
