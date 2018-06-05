package tester

import (
	"github.com/pkg/errors"
)

func (ts *Tester) Check(Host string, Port int, ProxyType int) (*Result, error) {
	if Host == "" || Port <= 0 {
		return nil, errors.New("Host and/or port has not been set")
	}

	//Check if port is open
	//isPortOpen := CheckIfPortOpen(Host, Port, ts.Config.ConnectTimeout)
	//if !isPortOpen {
	//	return &Result{PortOpen: false}, nil
	//}

	switch ProxyType {
	case TYPE_HTTP:
		return ts.TestHttp(Host, Port)
		break
	case TYPE_HTTPS:
		return ts.TestHttp(Host, Port)
		break
	case TYPE_SOCKS4:
		return ts.TestSocks4(Host, Port), nil
	case TYPE_SOCKS5:
		return ts.TestSocks4(Host, Port), nil
	case TYPE_UNKNOWN:
		//if result := ts.TestHttp("")
	}
	return nil, errors.New("Unknown proxy type")
}
