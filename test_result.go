package proxy

import "net"

type TestResult struct {
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

func NewJudgeTestResult() *TestResult {
	return &TestResult{
		Messages: make([]string, 0),
	}
}

//appends result messages
func (tr *TestResult) AppendMessages(msg []string){
	tr.Messages = append(tr.Messages, msg...)
}