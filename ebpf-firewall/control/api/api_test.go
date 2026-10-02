package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"ebpf-firewall/control/server"
)

// fakePolicy is a thread-safe in-memory server.Policy for unit tests (no
// kernel), mirroring the fake in control/server/server_test.go.
type fakePolicy struct {
	mu       sync.Mutex
	ips      []server.BlockedRule
	ports    []server.PortRule
	flows    []server.ConntrackEntry
	def      string
	statsErr bool
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{def: "allow"}
}

func (f *fakePolicy) BlockIP(string) error { return errors.New("unexpected write") }
func (f *fakePolicy) BlockIPWithAction(string, string) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) BlockIPWithActionPriority(string, string, uint32) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) UnblockIP(string) error { return errors.New("unexpected write") }
func (f *fakePolicy) ListBlockedIPs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.ips))
	for _, r := range f.ips {
		out = append(out, r.Cidr)
	}
	return out, nil
}
func (f *fakePolicy) ListBlockedRules() ([]server.BlockedRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]server.BlockedRule(nil), f.ips...), nil
}
func (f *fakePolicy) Clear() error { return errors.New("unexpected write") }
func (f *fakePolicy) Interface() string {
	return "lo0"
}
func (f *fakePolicy) AttachMode() string {
	return "xdpDriver"
}
func (f *fakePolicy) Stats() (server.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statsErr {
		return server.Stats{}, errors.New("boom")
	}
	return server.Stats{
		TotalPackets: 100,
		TotalBytes:   5000,
		DropPackets:  10,
		DropBytes:    600,
		PassPackets:  90,
		PassBytes:    4400,
	}, nil
}
func (f *fakePolicy) BlockPortRule(string, string, uint16, uint16) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) BlockPortRuleWithAction(string, string, uint16, uint16, string) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) BlockPortRuleWithActionPriority(string, string, uint16, uint16, string, uint32) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) UnblockPortRule(string, string, uint16, uint16) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) ListPortRules() ([]server.PortRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]server.PortRule(nil), f.ports...), nil
}
func (f *fakePolicy) ClearPortRules() error { return errors.New("unexpected write") }
func (f *fakePolicy) ListConntrack() ([]server.ConntrackEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]server.ConntrackEntry(nil), f.flows...), nil
}
func (f *fakePolicy) ClearConntrack() error { return errors.New("unexpected write") }
func (f *fakePolicy) SetDefaultPolicy(string) error {
	return errors.New("unexpected write")
}
func (f *fakePolicy) DefaultPolicy() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.def, nil
}

// errPolicy fails on every read, exercising the 500 paths.
type errPolicy struct{}

func (p *errPolicy) BlockIP(string) error                   { return errors.New("boom") }
func (p *errPolicy) BlockIPWithAction(string, string) error { return errors.New("boom") }
func (p *errPolicy) BlockIPWithActionPriority(string, string, uint32) error {
	return errors.New("boom")
}
func (p *errPolicy) UnblockIP(string) error            { return errors.New("boom") }
func (p *errPolicy) ListBlockedIPs() ([]string, error) { return nil, errors.New("boom") }
func (p *errPolicy) ListBlockedRules() ([]server.BlockedRule, error) {
	return nil, errors.New("boom")
}
func (p *errPolicy) Clear() error       { return errors.New("boom") }
func (p *errPolicy) Interface() string  { return "" }
func (p *errPolicy) AttachMode() string { return "" }
func (p *errPolicy) Stats() (server.Stats, error) {
	return server.Stats{}, errors.New("boom")
}
func (p *errPolicy) BlockPortRule(string, string, uint16, uint16) error {
	return errors.New("boom")
}
func (p *errPolicy) BlockPortRuleWithAction(string, string, uint16, uint16, string) error {
	return errors.New("boom")
}
func (p *errPolicy) BlockPortRuleWithActionPriority(string, string, uint16, uint16, string, uint32) error {
	return errors.New("boom")
}
func (p *errPolicy) UnblockPortRule(string, string, uint16, uint16) error { return errors.New("boom") }
func (p *errPolicy) ListPortRules() ([]server.PortRule, error) {
	return nil, errors.New("boom")
}
func (p *errPolicy) ClearPortRules() error { return errors.New("boom") }
func (p *errPolicy) ListConntrack() ([]server.ConntrackEntry, error) {
	return nil, errors.New("boom")
}
func (p *errPolicy) ClearConntrack() error         { return errors.New("boom") }
func (p *errPolicy) SetDefaultPolicy(string) error { return errors.New("boom") }
func (p *errPolicy) DefaultPolicy() (string, error) {
	return "", errors.New("boom")
}

// doGET issues a GET (or other method) against the API and returns the recorder.
func doRequest(t *testing.T, a *API, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

// decode unmarshals a JSON response body into v.
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding response %q: %v", rec.Body.String(), err)
	}
}

func TestHealth(t *testing.T) {
	a := New(newFakePolicy())
	rec := doRequest(t, a, http.MethodGet, "/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var h HealthResponse
	decode(t, rec, &h)
	if !h.OK {
		t.Errorf("health body = %+v, want ok", h)
	}
}

func TestStatus(t *testing.T) {
	p := newFakePolicy()
	p.mu.Lock()
	p.ips = []server.BlockedRule{{Cidr: "10.0.0.0/8", Action: "drop", Priority: 0}}
	p.ports = []server.PortRule{{Protocol: "tcp", Port: 22, Dst: "1.2.3.4", Action: "pass", Priority: 5}}
	p.def = "deny"
	p.mu.Unlock()

	rec := doRequest(t, New(p), http.MethodGet, "/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var s StatusResponse
	decode(t, rec, &s)
	want := StatusResponse{Interface: "lo0", AttachMode: "xdpDriver", DefaultPolicy: "deny", IPRuleCount: 1, PortRuleCount: 1}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("status = %+v, want %+v", s, want)
	}
}

func TestStats(t *testing.T) {
	rec := doRequest(t, New(newFakePolicy()), http.MethodGet, "/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("stats code = %d, want 200", rec.Code)
	}
	var st server.Stats
	decode(t, rec, &st)
	if st.TotalPackets != 100 || st.DropBytes != 600 || st.PassBytes != 4400 {
		t.Errorf("stats = %+v, want totals/drops/passes populated", st)
	}
}

func TestRules(t *testing.T) {
	p := newFakePolicy()
	p.mu.Lock()
	p.ips = []server.BlockedRule{{Cidr: "1.2.3.4", Action: "drop", Priority: 3}}
	p.ports = []server.PortRule{{Protocol: "udp", Port: 53, SPort: 0, Dst: "8.8.8.8", Action: "pass", Priority: 0}}
	p.mu.Unlock()

	rec := doRequest(t, New(p), http.MethodGet, "/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("rules code = %d, want 200", rec.Code)
	}
	var r RulesResponse
	decode(t, rec, &r)
	if len(r.BlockedRules) != 1 || r.BlockedRules[0].Cidr != "1.2.3.4" || r.BlockedRules[0].Priority != 3 {
		t.Errorf("blocked_rules = %+v", r.BlockedRules)
	}
	if len(r.PortRules) != 1 || r.PortRules[0].Protocol != "udp" || r.PortRules[0].Port != 53 {
		t.Errorf("port_rules = %+v", r.PortRules)
	}
}

func TestEmptyTablesRenderAsArrays(t *testing.T) {
	rec := doRequest(t, New(newFakePolicy()), http.MethodGet, "/rules")
	var r RulesResponse
	decode(t, rec, &r)
	if r.BlockedRules == nil || r.PortRules == nil {
		t.Errorf("empty tables must render as [], got %+v", r)
	}
	rec = doRequest(t, New(newFakePolicy()), http.MethodGet, "/conntrack")
	var c ConntrackResponse
	decode(t, rec, &c)
	if c.Flows == nil {
		t.Errorf("empty flows must render as [], got %+v", c)
	}
}

func TestConntrack(t *testing.T) {
	p := newFakePolicy()
	p.mu.Lock()
	p.flows = []server.ConntrackEntry{
		{Src: "10.0.0.1", Dst: "1.2.3.4", Sport: 50000, Dport: 22, Protocol: "tcp", State: "established", AgeSeconds: 1.5},
	}
	p.mu.Unlock()

	rec := doRequest(t, New(p), http.MethodGet, "/conntrack")
	if rec.Code != http.StatusOK {
		t.Fatalf("conntrack code = %d, want 200", rec.Code)
	}
	var c ConntrackResponse
	decode(t, rec, &c)
	if len(c.Flows) != 1 || c.Flows[0].State != "established" || c.Flows[0].Dport != 22 {
		t.Errorf("flows = %+v", c.Flows)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	a := New(newFakePolicy())
	for _, path := range []string{"/health", "/status", "/stats", "/rules", "/conntrack"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec := doRequest(t, a, method, path)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s code = %d, want 405", method, path, rec.Code)
			}
			if rec.Header().Get("Allow") != http.MethodGet {
				t.Errorf("%s %s Allow header = %q, want GET", method, path, rec.Header().Get("Allow"))
			}
		}
	}
}

func TestUnknownPath(t *testing.T) {
	rec := doRequest(t, New(newFakePolicy()), http.MethodGet, "/nope")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path code = %d, want 404", rec.Code)
	}
}

func TestErrorsReturn500(t *testing.T) {
	a := New(&errPolicy{})
	for _, path := range []string{"/status", "/stats", "/rules", "/conntrack"} {
		rec := doRequest(t, a, http.MethodGet, path)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("GET %s code = %d, want 500", path, rec.Code)
		}
		var body map[string]string
		decode(t, rec, &body)
		if body["error"] == "" {
			t.Errorf("GET %s body = %q, want an error field", path, rec.Body.String())
		}
	}
}
