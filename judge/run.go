package judge

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

var hostnameMarkers = []string{"mail",
                               "cache",
                               "squid",
                               "proxy"}

var ipMarkers = []string{"Client-Ip",
                         "HTTP_CLIENT_IP",
                         "FORWARDED",
                         "FORWARDED-FOR",
                         "FORWARDED-FOR_IP",
                         "X-FORWARDED",
}

var proxyMarkers = []string{
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
	showsIp := false
	showsProxyUsage := false
	
	result := &Result{
		Messages: make([]string, 0),
	}
	
	//getRealIp
	//realIp := self.getRealIp(req)
	remoteIp := self.getRemoteIp(req)
	
	//check hostnames for markers
	if msgs := self.CheckReverse(remoteIp.String()); len(msgs) > 0 {
		showsProxyUsage = true
		result.Messages = append(result.Messages, msgs...)
	}
	
	//combine x-forwarded-for
	self.normalizeXForwardedFor(req)
	
	self.debugLog(fmt.Sprintf("%v %v", showsIp, showsProxyUsage))
}

//Normalize X-Forwarded-For header based on cloudflare support and trusted proxies
func (self *Judge) normalizeXForwardedFor(req *http.Request) {
	forwardedFor := make([]string, 0)
	
	//define acceptable xforwarded for ips
	acceptablesForwardedIps := self.TrustedGatewaysIps
	if self.CloudFlareSupport {
		acceptablesForwardedIps = append(acceptablesForwardedIps, )
	}
	for tempIp := range strings.Split(req.Header.Get("X-Forwarded-For"), ",") {
		for accIp := range acceptablesForwardedIps {
			if tempIp != accIp {
				forwardedFor = append(forwardedFor)
			}
		}
	}
	//if forwardedFor is empty we can safely remove that header from our search
	//it would mean that proxy has not added any new ip
	if len(forwardedFor) == 0 {
		req.Header.Del("x-forwarded-for")
	}
}

//Gets remote ip
func (self *Judge) getRealIp(req *http.Request) string {
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
func (self *Judge) hasIpMarkers(req *http.Request) bool {
	for _, marker := range ipMarkers {
		if req.Header.Get(marker) != "" {
			self.debugLog(fmt.Sprintf("Found marker %s in headers", marker))
			return true
		}
	}
	//if cloudflare support is not enable, then check x-forwarded-for and go ahead
	if !self.CloudFlareSupport && req.Header.Get("X-Forwarded-For") == "" {
		self.debugLog("Found marker X-Forwarded-For in headers")
		return true
	}
	return false
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
