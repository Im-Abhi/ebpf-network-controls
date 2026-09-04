package server

// Command is a discrete operation the control server can execute.
type Command string

const (
	CmdBlock     Command = "block"
	CmdUnblock   Command = "unblock"
	CmdList      Command = "list"
	CmdStatus    Command = "status"
	CmdClear     Command = "clear"
	CmdStats     Command = "stats"
	CmdListPorts Command = "listports"
)

// Request is a single JSON command received over the control socket.
type Request struct {
	Command  Command `json:"command"`
	Value    string  `json:"value,omitempty"`
	Protocol string  `json:"protocol,omitempty"`
	Port     uint16  `json:"port,omitempty"`
}

// PortRule is a protocol+port+destination rule as returned by the server.
type PortRule struct {
	Protocol string `json:"protocol,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Dst      string `json:"dst"`
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
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	Blocked   []string   `json:"blocked,omitempty"`
	Count     int        `json:"count,omitempty"`
	Iface     string     `json:"interface,omitempty"`
	Attached  bool       `json:"attached,omitempty"`
	Stats     *Stats     `json:"stats,omitempty"`
	PortRules []PortRule `json:"port_rules,omitempty"`
}
