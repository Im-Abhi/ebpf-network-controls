package server

// Command is a discrete operation the control server can execute.
type Command string

const (
	CmdBlock      Command = "block"
	CmdUnblock    Command = "unblock"
	CmdList       Command = "list"
	CmdStatus     Command = "status"
	CmdClear      Command = "clear"
	CmdStats      Command = "stats"
	CmdListPorts  Command = "listports"
	CmdSetDefault Command = "setdefault"
	CmdDefault    Command = "default"
	CmdConntrack  Command = "conntrack"
)

// Request is a single JSON command received over the control socket.
type Request struct {
	Command  Command `json:"command"`
	Value    string  `json:"value,omitempty"`
	Protocol string  `json:"protocol,omitempty"`
	Port     uint16  `json:"port,omitempty"`
	SPort    uint16  `json:"sport,omitempty"`
	Action   string  `json:"action,omitempty"`
	Priority uint32  `json:"priority,omitempty"`
}

// PortRule is a protocol+port+destination rule as returned by the server.
// Action is the per-rule verdict ("pass" or "drop"); Priority orders rules
// that could match the same packet (higher wins; at equal priority the more
// specific port rule wins, and a tie against an IP rule resolves to DROP).
type PortRule struct {
	Protocol string `json:"protocol,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	SPort    uint16 `json:"sport,omitempty"`
	Dst      string `json:"dst"`
	Action   string `json:"action"`
	Priority uint32 `json:"priority,omitempty"`
}

// BlockedRule is a CIDR rule as returned by the server, including its action
// and priority.
type BlockedRule struct {
	Cidr     string `json:"cidr"`
	Action   string `json:"action"`
	Priority uint32 `json:"priority"`
}

// ConntrackEntry is a tracked TCP flow as returned by the server. State is
// one of "new", "established", or "closed"; AgeSeconds is the time since the
// last accepted packet on the flow.
type ConntrackEntry struct {
	Src        string  `json:"src"`
	Dst        string  `json:"dst"`
	Sport      uint16  `json:"sport"`
	Dport      uint16  `json:"dport"`
	Protocol   string  `json:"protocol"`
	State      string  `json:"state"`
	AgeSeconds float64 `json:"age_seconds"`
}

// Stats holds aggregated global packet and byte counters.
type Stats struct {
	TotalPackets uint64 `json:"total_packets"`
	TotalBytes   uint64 `json:"total_bytes"`
	DropPackets  uint64 `json:"drop_packets"`
	DropBytes    uint64 `json:"drop_bytes"`
	PassPackets  uint64 `json:"pass_packets"`
	PassBytes    uint64 `json:"pass_bytes"`
}

// Response is the JSON reply sent back to the client.
type Response struct {
	OK           bool          `json:"ok"`
	Error        string        `json:"error,omitempty"`
	Blocked      []string      `json:"blocked"`
	BlockedRules []BlockedRule `json:"blocked_rules"`
	Count        int           `json:"count,omitempty"`
	Iface        string        `json:"interface,omitempty"`
	Attached     bool          `json:"attached,omitempty"`
	Stats        *Stats        `json:"stats,omitempty"`
	PortRules    []PortRule       `json:"port_rules"`
	Conntrack    []ConntrackEntry `json:"conntrack"`
	Default      string           `json:"default_policy,omitempty"`
	AttachMode   string           `json:"attach_mode,omitempty"`
}
