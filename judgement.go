package proxy

import "net"

//Judgement contains information about a given proxy
//easyjson:json
type Judgement struct {
	//Possible values
	// 0: Non Anon: Your ip is known, proxy usage is known
	// 1: Non Anon: Your ip is known, proxy usage unknown
	// 2: Semi Anon: Your ip is unknown, proxy usage known
	// 3: Anon: Your ip is unknown, proxy usage unknown
	AnonType int      `json:"anon_type"`
	Messages []string `json:"messages"`
	Country  string   `json:"country"`
	RealIP   string   `json:"real_ip"`
	RemoteIP net.IP   `json:"remote_ip"`
}

//AppendMessages appends result messages
func (tr *Judgement) AppendMessages(msg []string) {
	tr.Messages = append(tr.Messages, msg...)
}
