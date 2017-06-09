package judge

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

var hostnameMarkers = []string{"cache",
	"squid",
	"proxy"}

var proxyHeaderMarkers = []string{"Client-Ip",
	"HTTP_CLIENT_IP",
	"FORWARDED",
	"FORWARDED-FOR",
	"FORWARDED-FOR-IP",
	"X-FORWARDED",
	"X-FORWARDED-FOR",
	"PROXY_CONNECTION",
	"Via",
	"X-Proxy-Id",
	"X-Bluecoat-Via",
}

func (self *Judge) Start() {
	http.HandleFunc("/", self.analyzeRequest)
	err := http.ListenAndServe(fmt.Sprintf(":%d", self.Port), nil) // set listen port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func (self *Judge) analyzeRequest(w http.ResponseWriter, req *http.Request) {
	//Debug Block
	self.debugLog(formatRequest(req))

	//set up markers
	showsRealIp := false
	showsProxyUsage := false

	result := &Result{
		Messages: make([]string, 0),
	}

	//if cloudflare is supported set the country
	if self.CloudFlareSupport {
		result.Country = req.Header.Get("Cf-Ipcountry")
	}

	//getRealIpFromPost
	realIp := self.getRealIpFromPost(req)
	remoteIp := self.getRemoteIp(req)

	//check hostnames for markers
	if msgs := self.CheckReverse(remoteIp.String()); len(msgs) > 0 {
		showsProxyUsage = true
		result.Messages = append(result.Messages, msgs...)
	}

	//normalize xforwardedFor removing cloudflare and trusted gateways
	self.normalizeXForwardedFor(req)

	//search our ip in all headers
	if msg := self.checkIpInHeaders(req, realIp); len(msg) > 0 {
		showsRealIp = true
		result.Messages = append(result.Messages, msg...)
	}

	//check headers
	if msg := self.hasProxyHeaderMarkings(req); len(msg) > 0 {
		showsProxyUsage = true
		result.Messages = append(result.Messages, msg...)
	}

	//final judgement
	if showsRealIp {
		if showsProxyUsage {
			result.Type = 0
		} else {
			result.Type = 1
		}
	} else {
		if showsProxyUsage {
			result.Type = 2
		} else {
			result.Type = 3
		}
	}

	//todo: write json response to output
	b, err := json.Marshal(&result)
	if err != nil {
		self.debugLog(fmt.Sprintf("Error on json.Marshal: %+v", err))
		http.Error(w, "Error on marshaling", http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func (self *Judge) checkIpInHeaders(req *http.Request, realIp string) []string {
	msg := make([]string, 0)
	for k, v := range req.Header {
		if strings.Contains(strings.Join(v, ","), realIp) == false {
			continue
		}
		//found our ip in the header
		msg = append(msg, fmt.Sprintf("Found real ip in the header [%s]", k))
	}
	return msg
}

//Normalize X-Forwarded-For header based on cloudflare support and trusted proxies
func (self *Judge) normalizeXForwardedFor(req *http.Request) {
	forwardedFor := make([]string, 0)

	//define acceptable xforwarded for ips
	acceptablesForwardedIps := self.TrustedGatewaysIps
	if self.CloudFlareSupport {
		acceptablesForwardedIps = append(acceptablesForwardedIps)
	}

	//loop through ip and remove those which are acceptable
	for _, tempIp := range strings.Split(req.Header.Get("X-Forwarded-For"), ",") {
		for _, accIp := range acceptablesForwardedIps {
			if tempIp == accIp {
				continue
			}
			forwardedFor = append(forwardedFor, tempIp)
		}
	}
	//if forwardedFor is empty we can safely remove that header from our search
	//it would mean that proxy has not added any new ip
	if len(forwardedFor) == 0 {
		req.Header.Del("x-forwarded-for")
	}
}

//Gets real ip
func (self *Judge) getRealIpFromPost(req *http.Request) string {
	realIp := ""
	if err := req.ParseForm(); err == nil {
		realIp = req.Form.Get("real-ip")
	}
	return realIp
}

//
func (self *Judge) getRemoteIp(req *http.Request) net.IP {
	//get Remote ip. Replace it with cloudflare value if needed
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	remoteIp := net.ParseIP(ip)

	//If cloudflare support is enabled, then replace remote ip with
	//contents of CF-Connecting-Ip header
	//Also add current remote ip to the array of ips which have to be removed from
	//forwarded for header
	if self.CloudFlareSupport {
		if ip = req.Header.Get("CF-Connecting-IP"); ip != "" {
			temp := net.ParseIP(ip)
			if temp != nil {
				remoteIp = temp
			}
		}
	}
	return remoteIp
}

func (self *Judge) hasProxyHeaderMarkings(req *http.Request) []string {
	msg := make([]string, 0)
	for _, marker := range proxyHeaderMarkers {
		if req.Header.Get(marker) != "" {
			msg = append(msg, fmt.Sprintf("Header [%s] is present", marker))
		}
	}
	return msg
}

//Checks if name contain certain markers
func (self *Judge) CheckReverse(ip string) []string {
	res := make([]string, 0)
	names, err := net.LookupAddr(ip)
	if err != nil {
		self.debugLog(fmt.Sprintf("Error on resolving host for '%s' - [%+v]", ip, err))
		return res
	}
	//look for pattern
	fullNames := strings.Join(names, ",")
	for _, mark := range hostnameMarkers {
		if strings.Contains(fullNames, mark) {
			self.debugLog(fmt.Sprintf("Found marker %s in the hostname %s", mark, fullNames))
			res = append(res, fmt.Sprintf("Hostname contains %s", mark))
		}
	}
	return res
}

func (self *Judge) debugLog(msg string) {
	if self.DebugEnabled == false {
		return
	}
	fmt.Println(msg)
}
