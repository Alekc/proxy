package judge

import (
	"fmt"
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

func (j *Judge) Start() {
	j.logger.Infof("Starting proxy judge v. %s", version)

	//load cf ranges
	if j.CloudFlareSupport {
		j.logger.Debug("Loading cf ip ranges")
		loadCfRanges()
		j.logger.Debug("Cf ranges loaded")
	}
	//listen
	http.HandleFunc("/", j.analyzeRequest)
	j.logger.Debugf("Listening on %s", j.ListenAddress)
	err := http.ListenAndServe(j.ListenAddress, nil) // set listen port
	if err != nil {
		j.logger.WithError(err).Fatal("ListenAndServe fail")
	}
}

func (j *Judge) analyzeRequest(w http.ResponseWriter, req *http.Request) {
	//Debug Block
	j.logRequest(req)

	//set up markers
	showsRealIP := false
	showsProxyUsage := false

	result := NewJudgement()

	//if cloudflare is supported get the country from header
	if j.CloudFlareSupport {
		result.Country = req.Header.Get("Cf-IpCountry")
	}

	//getRealIPFromPost
	result.RealIP = j.getRealIPFromPost(req)
	result.RemoteIP = j.getRemoteIp(req)

	//check reverse hostname of proxy ip for markers
	if msg := j.CheckReverse(result.RemoteIP.String()); len(msg) > 0 {
		showsProxyUsage = true
		result.AppendMessages(msg)
	}

	//normalize xforwardedFor removing cloudflare and trusted gateways
	j.normalizeXForwardedFor(req)

	//search our ip in all headers
	if result.RealIP != "" {
		if msg := j.checkIPInHeaders(req, result.RealIP); len(msg) > 0 {
			showsRealIP = true
			result.AppendMessages(msg)
		}
	}

	//check headers
	if msg := j.hasProxyHeaderMarkers(req); len(msg) > 0 {
		showsProxyUsage = true
		result.AppendMessages(msg)
	}

	//final judgement
	if showsRealIP {
		if showsProxyUsage {
			j.logger.
				WithField("judgement", "shows real ip, shows proxy usage").
				Debug("judgement finished")
			result.AnonType = 0
		} else {
			j.logger.
				WithField("judgement", "shows real ip, hides proxy usage").
				Debug("judgement finished")
			result.AnonType = 1
		}
	} else {
		if showsProxyUsage {
			j.logger.
				WithField("judgement", "doesn't show real ip, shows proxy usage").
				Debug("judgement finished")
			result.AnonType = 2
		} else {
			j.logger.
				WithField("judgement", "doesn't show real ip, doesn't show proxy usage").
				Debug("judgement finished")
			result.AnonType = 3
		}
	}

	encodedBody, _ := result.MarshalJSON()
	_, _ = w.Write(encodedBody)
	j.logger.
		WithField("body", string(encodedBody)).
		Info("http response")
}

func (j *Judge) checkIPInHeaders(req *http.Request, realIP string) []string {
	msg := make([]string, 0)
	for k, v := range req.Header {
		if !strings.Contains(strings.Join(v, ","), realIP) {
			continue
		}
		//found our ip in the header
		j.logger.
			WithField("header_name", k).
			WithField("header_value", v).
			Infof("Found real ip in headers")
		msg = append(msg, fmt.Sprintf("Found real ip in the header [%s]", k))
	}
	return msg
}

//Normalize X-Forwarded-For header based on cloudflare support and trusted gateways
func (j *Judge) normalizeXForwardedFor(req *http.Request) {
	forwardedFor := make([]string, 0)

	//loop through ip and remove those which are acceptable
	headerSlices := req.Header[textproto.CanonicalMIMEHeaderKey("X-Forwarded-For")]
	for _, headerValue := range headerSlices {
		for _, tempIP := range strings.Split(headerValue, ",") { //in case we have multiple entries
			//if cloudflare support is enabled, check if ip belongs to its network
			if j.CloudFlareSupport && ipBelongsToCfNetwork(net.ParseIP(tempIP)) {
				continue
			}
			//check if ip is in the range of trusted gateways.
			found := false
			for _, trustedIP := range j.TrustedGatewaysIps {
				if tempIP == trustedIP {
					found = true
					break
				}
			}
			if !found {
				forwardedFor = append(forwardedFor, tempIP)
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
func (j *Judge) getRealIPFromPost(req *http.Request) string {
	realIP := ""
	if err := req.ParseForm(); err == nil {
		realIP = req.Form.Get("real-ip")
	} else {
		j.logger.WithError(err).Warn("Couldn't get real ip")
	}
	return realIP
}

//
func (j *Judge) getRemoteIp(req *http.Request) net.IP {
	//get Remote ip. Replace it with cloudflare value if needed
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	remoteIp := net.ParseIP(ip)

	//If cloudflare support is enabled, then replace remote ip with
	//contents of CF-Connecting-Ip header
	//Also add current remote ip to the array of ips which have to be removed from
	//forwarded for header
	if j.CloudFlareSupport {
		if ip = req.Header.Get("CF-Connecting-IP"); ip != "" {
			temp := net.ParseIP(ip)
			if temp != nil {
				remoteIp = temp
			}
		}
	}
	return remoteIp
}

//checks if headers have certain markers, i.e. FORWARDED-FOR
func (j *Judge) hasProxyHeaderMarkers(req *http.Request) []string {
	msg := make([]string, 0)
	for _, marker := range proxyHeaderMarkers {
		key := textproto.CanonicalMIMEHeaderKey(marker)
		if val, ok := req.Header[key]; ok {
			j.logger.
				WithField("header_name", marker).
				WithField("header_value", strings.Join(val, ",")).
				Debug("Header marker found")
			msg = append(msg, fmt.Sprintf("Header [%s] is present", marker))
		}
	}
	return msg
}

//Checks if name contain certain markers
func (j *Judge) CheckReverse(ip string) []string {
	res := make([]string, 0)
	names, err := net.LookupAddr(ip)
	if err != nil {
		j.logger.
			WithError(err).
			Error("error on ip reversal")
		return res
	}
	//look for patterns
	fullNames := strings.Join(names, ",")
	for _, mark := range hostnameMarkers {
		if strings.Contains(fullNames, mark) {
			j.logger.
				WithField("mark", mark).
				WithField("resolved_hostname", fullNames).
				Info("Found host marker")
			res = append(res, fmt.Sprintf("Hostname contains %s", mark))
		}
	}
	return res
}
