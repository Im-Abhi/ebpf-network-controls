// Package api exposes a read-only HTTP view of the firewall's live state.
//
// It wraps the same server.Policy interface the Unix-socket control plane
// drives, so it can be unit-tested against a fake without a kernel and never
// mutates policy: the handlers only call the read/List methods of Policy
// (never Block/Unblock/Clear/SetDefault).
//
// Endpoints:
//
//	GET /health    -> {"ok":true}
//	GET /status    -> interface, attach mode, default policy, rule counts
//	GET /stats     -> total/drop/pass packet+byte counters
//	GET /rules     -> IP/CIDR rules and protocol/port rules
//	GET /conntrack -> {"flows":[...]} tracked TCP flows
//
// Bind it to loopback: /rules and /conntrack expose security-relevant
// information even though the API is read-only.
package api

import (
	"encoding/json"
	"net/http"

	"ebpf-firewall/control/server"
)

// StatusResponse is the body of GET /status. AttachMode is empty until the
// program is attached, which doubles as the attached indicator.
type StatusResponse struct {
	Interface     string `json:"interface"`
	AttachMode    string `json:"attach_mode"`
	DefaultPolicy string `json:"default_policy"`
	IPRuleCount   int    `json:"ip_rule_count"`
	PortRuleCount int    `json:"port_rule_count"`
}

// RulesResponse is the body of GET /rules.
type RulesResponse struct {
	BlockedRules []server.BlockedRule `json:"blocked_rules"`
	PortRules    []server.PortRule    `json:"port_rules"`
}

// ConntrackResponse is the body of GET /conntrack. The flow table is wrapped
// so future fields can be added without breaking clients.
type ConntrackResponse struct {
	Flows []server.ConntrackEntry `json:"flows"`
}

// HealthResponse is the body of GET /health.
type HealthResponse struct {
	OK bool `json:"ok"`
}

// API is the read-only HTTP handler set. Create it with New and mount its
// ServeHTTP method on an http.Server.
type API struct {
	policy server.Policy
	mux    *http.ServeMux
}

// New builds the API around a Policy. The policy is never mutated.
func New(p server.Policy) *API {
	a := &API{policy: p, mux: http.NewServeMux()}
	a.mux.HandleFunc("/health", a.get(a.handleHealth))
	a.mux.HandleFunc("/status", a.get(a.handleStatus))
	a.mux.HandleFunc("/stats", a.get(a.handleStats))
	a.mux.HandleFunc("/rules", a.get(a.handleRules))
	a.mux.HandleFunc("/conntrack", a.get(a.handleConntrack))
	return a
}

// ServeHTTP routes a request to the matching endpoint, rejecting non-GET
// methods with 405.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// get wraps a handler so only GET requests reach it; anything else gets a 405
// with an Allow header.
func (a *API) get(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{OK: true})
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	def, err := a.policy.DefaultPolicy()
	if err != nil {
		writeErr(w, err)
		return
	}
	blocked, err := a.policy.ListBlockedRules()
	if err != nil {
		writeErr(w, err)
		return
	}
	ports, err := a.policy.ListPortRules()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, StatusResponse{
		Interface:     a.policy.Interface(),
		AttachMode:    a.policy.AttachMode(),
		DefaultPolicy: def,
		IPRuleCount:   len(blocked),
		PortRuleCount: len(ports),
	})
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.policy.Stats()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (a *API) handleRules(w http.ResponseWriter, r *http.Request) {
	blocked, err := a.policy.ListBlockedRules()
	if err != nil {
		writeErr(w, err)
		return
	}
	ports, err := a.policy.ListPortRules()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, RulesResponse{
		BlockedRules: nonNil(blocked),
		PortRules:    nonNil(ports),
	})
}

func (a *API) handleConntrack(w http.ResponseWriter, r *http.Request) {
	flows, err := a.policy.ListConntrack()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ConntrackResponse{Flows: nonNil(flows)})
}

// writeErr reports a backend failure as a 500 JSON error.
func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

// writeJSON encodes v as JSON with the given status and a JSON content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// nonNil guarantees a JSON array in the response even when a List method
// returns nil (so an empty table renders as [] rather than null).
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
