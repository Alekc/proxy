package main

import (
	"github.com/alekc/proxy/judge"
	"gopkg.in/alecthomas/kingpin.v2"
	"strings"
)

var (
	listenAddress = kingpin.Flag("listenAddress", "Listen Address.").Short('l').Default(":8080").String()
	debugEnabled  = kingpin.Flag("debug", "Debug Output.").Short('d').Bool()
	cfSupport     = kingpin.Flag("cloudflare", "Enable cloudflare support.").Short('c').Default("false").Bool()
	trustedGw     = kingpin.Flag("gw", "Trusted gateways which add via headers separated by commas").Short('g').Default("").String()
)

func main() {
	kingpin.Parse()

	//port := flag.Int64("port",8080,"Listening port")
	pJudge := judge.Create()
	pJudge.ListenAddress = *listenAddress
	pJudge.DebugEnabled = *debugEnabled
	pJudge.CloudFlareSupport = *cfSupport
	if len(*trustedGw) > 0 {
		pJudge.TrustedGatewaysIps = strings.Split(*trustedGw, ",")
	}

	pJudge.Start()
}
