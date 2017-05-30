package tester

type Result struct {
	Ok           bool
	Err          error
	PortOpen     bool
	Body         string
	ResponseCode int
}
