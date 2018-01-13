package proxy

import "net"

//easyjson:json
type Judgement struct {
	//Possible values
	// 0: Non Anon: Your ip is known, proxy usage is known
	// 1: Non Anon: Your ip is known, proxy usage unknown
	// 2: Semi Anon: Your ip is unknown, proxy usage known
	// 3: Anon: Your ip is unknown, proxy usage unknown
	Type     int
	Messages []string
	Country  string
	RealIp   string
	RemoteIp net.IP
}

func NewJudgement() *Judgement {
	return &Judgement{
		Messages: make([]string, 0),
	}
}

//appends result messages
func (tr *Judgement) AppendMessages(msg []string){
	tr.Messages = append(tr.Messages, msg...)
}