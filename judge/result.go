package judge

type Result struct {
	//Possible values
	// 0: Non Anon: Show your ip, knows that you are using proxies.
	// 2: Non Anon: Doesnt show your ip, know that you are using proxies
	// 3: Anon ip: unknown, proxy fact: known
	// 4: Elite: ip unknown, proxy fact: unknown
	Type int
	ProxyMarks1 []string
	ProxyMarks2 []string
	ProxyMarks3 []string
	ProxyMarks4 []string
	
	Messages []string
}
