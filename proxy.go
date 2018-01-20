package proxy

import "fmt"

//easyjson:json
type Proxy struct {
	Ip   string
	Port string //todo: change to int
	Type int
}

func (px *Proxy) ToString() string {
	return fmt.Sprintf("%s:%s", px.Ip, px.Port)
}
