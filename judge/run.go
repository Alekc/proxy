package judge

import (
	"fmt"
	"github.com/alekc/proxy"
	"log"
	"net"
	"net/http"
	"net/textproto"
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
	"X-Iwproxy",
}

func (jd *Judge) Start() {
	//load cf ranges
	if jd.CloudFlareSupport {
		loadCfRanges()
	}
	//listen
	http.HandleFunc("/", jd.analyzeRequest)
	err := http.ListenAndServe(fmt.Sprintf(jd.ListenAddress), nil) // set listen port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func (jd *Judge) analyzeRequest(w http.ResponseWriter, req *http.Request) {
	//Debug Block
	jd.debugLog(formatRequest(req))

	//set up markers
	showsRealIp := false
	showsProxyUsage := false

	result := proxy.NewJudgement()

	//if cloudflare is supported set the country
	if jd.CloudFlareSupport {
		result.Country = req.Header.Get("Cf-Ipcountry")
	}

	//getRealIpFromPost
	result.RealIp = jd.getRealIpFromPost(req)
	result.RemoteIp = jd.getRemoteIp(req)

	//check hostnames for markers
	if msg := jd.CheckReverse(result.RemoteIp.String()); len(msg) > 0 {
		showsProxyUsage = true
		result.AppendMessages(msg)
	}

	//normalize xforwardedFor removing cloudflare and trusted gateways
	jd.normalizeXForwardedFor(req)

	//search our ip in all headers
	if result.RealIp != "" {
		if msg := jd.checkIpInHeaders(req, result.RealIp); len(msg) > 0 {
			showsRealIp = true
			result.AppendMessages(msg)
		}
	}

	//check headers
	if msg := jd.hasProxyHeaderMarkings(req); len(msg) > 0 {
		showsProxyUsage = true
		result.AppendMessages(msg)
	}

	//final judgement
	if showsRealIp {
		if showsProxyUsage {
			result.AnonType = 0
		} else {
			result.AnonType = 1
		}
	} else {
		if showsProxyUsage {
			result.AnonType = 2
		} else {
			result.AnonType = 3
		}
	}

	b, _ := result.MarshalJSON()
	w.Write(b)
}

func (jd *Judge) checkIpInHeaders(req *http.Request, realIp string) []string {
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
func (jd *Judge) normalizeXForwardedFor(req *http.Request) {
	forwardedFor := make([]string, 0)

	//loop through ip and remove those which are acceptable
	headerSlices := req.Header[textproto.CanonicalMIMEHeaderKey("X-Forwarded-For")]
	for _, headerValue := range headerSlices {
		for _, tempIp := range strings.Split(string(headerValue), ",") { //in case we have multiple entries
			//if cloudflare support is enabled, check if ip belongs to its network
			if jd.CloudFlareSupport && ipBelongsToCfNetwork(net.ParseIP(tempIp)) {
				continue
			}
			//check if ip is in the range of trusted gateways.
			found := false
			for _, accIp := range jd.TrustedGatewaysIps {
				if tempIp == accIp {
					found = true
					break
				}
			}
			if !found {
				forwardedFor = append(forwardedFor, tempIp)
			}
		}
	}
	//if forwardedFor is empty we can safely remove that header from our search
	//it would mean that proxy has not added any new ip
	if len(forwardedFor) == 0 {
		req.Header.Del("x-forwarded-for")
	}
}

//Gets real ip
func (jd *Judge) getRealIpFromPost(req *http.Request) string {
	realIp := ""
	if err := req.ParseForm(); err == nil {
		realIp = req.Form.Get("real-ip")
	} else {
		jd.debugLog(fmt.Sprintf("Error %+v", err))
	}
	return realIp
}

//
func (jd *Judge) getRemoteIp(req *http.Request) net.IP {
	//get Remote ip. Replace it with cloudflare value if needed
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	remoteIp := net.ParseIP(ip)

	//If cloudflare support is enabled, then replace remote ip with
	//contents of CF-Connecting-Ip header
	//Also add current remote ip to the array of ips which have to be removed from
	//forwarded for header
	if jd.CloudFlareSupport {
		if ip = req.Header.Get("CF-Connecting-IP"); ip != "" {
			temp := net.ParseIP(ip)
			if temp != nil {
				remoteIp = temp
			}
		}
	}
	return remoteIp
}

func (jd *Judge) hasProxyHeaderMarkings(req *http.Request) []string {
	msg := make([]string, 0)
	for _, marker := range proxyHeaderMarkers {
		if req.Header.Get(marker) != "" {
			msg = append(msg, fmt.Sprintf("Header [%s] is present", marker))
		}
	}
	return msg
}

//Checks if name contain certain markers
func (jd *Judge) CheckReverse(ip string) []string {
	res := make([]string, 0)
	names, err := net.LookupAddr(ip)
	if err != nil {
		//jd.debugLog(fmt.Sprintf("Error on resolving host for '%s' - [%+v]", ip, err))
		return res
	}
	//look for pattern
	fullNames := strings.Join(names, ",")
	for _, mark := range hostnameMarkers {
		if strings.Contains(fullNames, mark) {
			jd.debugLog(fmt.Sprintf("Found marker %s in the hostname %s", mark, fullNames))
			res = append(res, fmt.Sprintf("Hostname contains %s", mark))
		}
	}
	return res
}

func (jd *Judge) debugLog(msg string) {
	if jd.DebugEnabled == false {
		return
	}
	fmt.Println(msg)
}
