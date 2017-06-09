package tester

import "time"

type Result struct {
	Ok           bool
	Err          error
	PortOpen     bool
	Body         string
	ResponseCode int
	ExecTime     time.Duration
}
