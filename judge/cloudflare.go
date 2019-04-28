package judge

import (
	"context"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"go.opencensus.io/trace"

	"gopkg.in/resty.v1"
)

//downloadLiveRanges downloads cloudflare network ranges
func downloadLiveRanges(ctx context.Context, log *logrus.Logger) (string, error) {
	_, span := trace.StartSpan(ctx, "judge.loadLiveCfRanges")
	defer span.End()

	url := "https://www.cloudflare.com/ips-v4"
	log.Debug()
	resp, err := resty.R().Get(url)
	if err != nil {
		log.WithError(err).
			WithField("url", url).
			Error("error during download")
		return "", err
	}
	if !resp.IsSuccess() {
		log.WithField("response_code", resp.StatusCode()).
			WithField("body", resp.Body()).
			WithField("url", url).
			Error("invalid status code")
		return "", nil
	}
	return string(resp.Body()), nil
}

//loadCfRanges loads ranges for cloudflare
func (j *Judge) loadCfRanges(ctx context.Context) {
	_, span := trace.StartSpan(ctx, "judge.loadCfRanges")
	defer span.End()

	//get values from live site
	ranges, err := downloadLiveRanges(ctx, j.logger)
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

// Checks if ip belongs to a cloudflare network.
func ipBelongsToCfNetwork(ranges []*net.IPNet, ip net.IP) bool {
	for _, cidr := range ranges {
		belongs := cidr.Contains(ip)
		if belongs {
			return true
		}
	}
	return false
}
