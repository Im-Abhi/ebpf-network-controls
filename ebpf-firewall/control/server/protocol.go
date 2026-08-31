package server

// Command is a discrete operation the control server can execute.
type Command string

const (
	CmdBlock   Command = "block"
	CmdUnblock Command = "unblock"
	CmdList    Command = "list"
	CmdStatus  Command = "status"
	CmdClear   Command = "clear"
)

// Request is a single JSON command received over the control socket.
type Request struct {
	Command Command `json:"command"`
	Value   string  `json:"value,omitempty"`
}

// Response is the JSON reply sent back to the client.
type Response struct {
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Blocked  []string `json:"blocked,omitempty"`
	Count    int      `json:"count,omitempty"`
	Iface    string   `json:"interface,omitempty"`
	Attached bool     `json:"attached,omitempty"`
}
