package proxy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var proxyRegex = regexp.MustCompile(`^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])):(\d{1,5})$`)

//Proxy represent an proxy object containing ip, port, and the proxy type
//easyjson:json
type Proxy struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Type int    `json:"type,omitempty"`
}

//ToString converts proxy to ip:port format
func (v *Proxy) ToString() string {
	return fmt.Sprintf("%s:%d", v.IP, v.Port)
}

//FromIpv4String converts ipv4 string (xxx.xx.xxx.xxx:xxxxx) to a Proxy object
func FromIpv4String(proxyString string) (*Proxy, error) {
	if proxyString == "" {
		return nil, errors.New("input string is empty")
	}

	//extract ip and port
	matchResult := proxyRegex.FindAllStringSubmatch(proxyString, -1)
	if matchResult == nil || (len(matchResult) != 1 && len(matchResult[0]) != 3) {
		return nil, errors.New("this is not a valid ipv4 address")
	}

	//convert port to appropriate type
	port, _ := strconv.Atoi(matchResult[0][2])
	if !(port > 0 && port <= 65535) {
		return nil, errors.New("invalid port")
	}
	px := &Proxy{
		IP:   matchResult[0][1],
		Port: port,
		Type: 0,
	}
	return px, nil
}
