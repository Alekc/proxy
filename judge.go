package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	"github.com/alekc/proxy/cloudflare"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

const version = "0.1.0"

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

//Judge listens for incoming judge request
type Judge struct {
	ListenAddress string
	//Set to true if you want support for judge being behind the cloudflare infrastructure
	CloudFlareSupport bool
	//List of trusted gateways. If your judge instance is behind some load-balancer/gateway
	//which adds it's ip to x-forwarded-for header you might want to add it here.
	TrustedGatewaysIps []string
	logger             *logrus.Logger
	cfIPRanges         []*net.IPNet
}

//Create new Judge instance
func Create() *Judge {
	obj := new(Judge)
	obj.ListenAddress = ":8080"
	obj.CloudFlareSupport = true

	//default logger (only errors are visible)
	obj.logger = logrus.New()
	obj.logger.Out = os.Stdout
	obj.logger.SetLevel(logrus.ErrorLevel)

	return obj
}

//SetLogger sets new logger instance
func (j *Judge) SetLogger(log *logrus.Logger) {
	j.logger = log
}

//newJudgement creates new Judgement instance
func newJudgement() *Judgement {
	return &Judgement{
		Messages: make([]string, 0),
	}
}

//Run the judge
func (j *Judge) Run() {
	j.logger.Infof("Starting proxy judge v. %s", version)

	//load cf ranges
	if j.CloudFlareSupport {
		j.logger.Debug("Loading cf ip ranges")
		j.loadCfRanges(context.TODO())
		j.logger.Info("Cf ranges loaded")
	}
	//listen
	http.HandleFunc("/", j.analyzeRequest)
	j.logger.Debugf("Listening on %s", j.ListenAddress)
	err := http.ListenAndServe(j.ListenAddress, nil) // set listen port
	if err != nil {
		j.logger.WithError(err).Fatal("ListenAndServe fail")
	}
}

//analyzeRequest analyze proxy state based
func (j *Judge) analyzeRequest(w http.ResponseWriter, req *http.Request) {
	//Debug Block
	j.logRequest(req)

	//set up markers
	showsRealIP := false
	showsProxyUsage := false

	result := newJudgement()

	//if cloudflare is supported, get the country from header
	//todo enable support for geoip without cloudflare
	if j.CloudFlareSupport {
		result.Country = req.Header.Get("Cf-IpCountry")
	}

	//getRealIPFromPost
	result.RealIP = j.getRealIPFromPost(req)
	result.RemoteIP = j.getRemoteIP(req)

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
			if j.CloudFlareSupport && cloudflare.IpBelongsToCfNetwork(j.cfIPRanges, net.ParseIP(tempIP)) {
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

//getRealIPFromPost returns real ip if returned from the request
func (j *Judge) getRealIPFromPost(req *http.Request) string {
	realIP := ""
	if err := req.ParseForm(); err == nil {
		realIP = req.Form.Get("real-ip")
	} else {
		j.logger.WithError(err).Warn("Couldn't get real ip")
	}
	return realIP
}

//getRemoteIP returns connecting ip from request.
//if cloudflare support is enabled, then the CF-Connecting-IP value is used
func (j *Judge) getRemoteIP(req *http.Request) net.IP {
	//get Remote ip. Replace it with cloudflare value if needed
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	remoteIP := net.ParseIP(ip)

	//If cloudflare support is enabled, then replace remote ip with
	//contents of CF-Connecting-Ip header
	//Also add current remote ip to the array of ips which have to be removed from
	//forwarded for header
	if j.CloudFlareSupport {
		if ip = req.Header.Get("CF-Connecting-IP"); ip != "" {
			temp := net.ParseIP(ip)
			if temp != nil {
				remoteIP = temp
			}
		}
	}
	return remoteIP
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

//CheckReverse attempts to reverse ip address, and look for certain markers.
//for example proxy1.company.com
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

var excludedHeaders = map[string]interface{}{
	"Connection":                nil,
	"Accept-Encoding":           nil,
	"Cf-Ipcountry":              nil,
	"Accept":                    nil,
	"Accept-Language":           nil,
	"Cf-Ray":                    nil,
	"X-Forwarded-Proto":         nil,
	"Upgrade-Insecure-Requests": nil,
	"Cache-Control":             nil,
	"Cookie":                    nil,
	"Cf-Connecting-Ip":          nil,
	"Cf-Visitor":                nil,
	"Content-Type":              nil,
	"Content-Length":            nil,
	"User-Agent":                nil,
	"Via":                       nil,
	"X-Forwarded-For":           nil,
	"X-Proxy-Id":                nil,
	"Dnt":                       nil,
}

// logRequest generates ascii representation of a request
func (j *Judge) logRequest(r *http.Request) {
	// Loop through headers
	for name, headers := range r.Header {
		//Do not debug known headers
		if _, ok := excludedHeaders[name]; ok {
			continue
		}
		for _, h := range headers {
			j.logger.
				WithField("header_key", name).
				WithField("header_value", h).
				Warn("unknown header")
		}
	}
}

//loadCfRanges loads ranges for cloudflare
func (j *Judge) loadCfRanges(ctx context.Context) {
	_, span := trace.StartSpan(ctx, "judge.loadCfRanges")
	defer span.End()

	//get values from live site
	ranges, err := cloudflare.DownloadLiveRanges(ctx, j.logger)
	switch {
	case err != nil:
	case ranges == "":
		j.logger.Debug("loading default ranges")
		ranges = `
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
	default:
		j.logger.Debug("downloaded cf ranges")
	}

	//split result and add it to our ranges
	ipRanges := strings.Split(ranges, "\n")
	for _, cidr := range ipRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		//skip on error
		if err != nil {
			j.logger.WithError(err).Error("error on cidr parsing")
			continue
		}
		j.logger.WithField("cidr", cidr).Debug("added cidr to cf ranges")
		j.cfIPRanges = append(j.cfIPRanges, ipNet)
	}
}
