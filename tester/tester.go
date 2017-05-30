package tester

type Tester struct {
	Config Config
	RealIp string
}

//Default Tester Instance
var DefaultTester = New()

func New() *Tester {
	obj := &Tester{
		Config: DefaultConfig,
	}
	return obj
}
