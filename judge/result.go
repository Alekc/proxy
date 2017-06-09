package judge

type Result struct {
	//Possible values
	// 0: Non Anon: Your ip is known, proxy usage is known
	// 1: Non Anon: Your ip is known, proxy usage unknown
	// 2: Semi Anon: Your ip is unknown, proxy usage known
	// 3: Anon: Your ip is unknown, proxy usage unknown
	Type     int
	Messages []string
	Country  string
}
