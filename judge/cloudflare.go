package judge

import (
	"net"
	"strings"
)

var cfRanges []*net.IPNet

// load cloudflare network ranges
func loadCfRanges() {
	//todo : add dynamic loading from https://www.cloudflare.com/ips-v4
	body := `
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/12
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32`

	ipRanges := strings.Split(body, "\n")
	for _, cidr := range ipRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		//skip on error
		if err != nil {
			continue
		}
		cfRanges = append(cfRanges, ipNet)
	}
}

// Checks if ip belongs to a cloudflare network.
func ipBelongsToCfNetwork(ip net.IP) bool {
	for _, cidr := range cfRanges {
		belongs := cidr.Contains(ip)
		if belongs {
			return true
		}
	}
	return false
}
