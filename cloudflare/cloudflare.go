package cloudflare

import (
	"context"
	"github.com/sirupsen/logrus"
	"net"

	"go.opencensus.io/trace"

	"gopkg.in/resty.v1"
)

//downloadLiveRanges downloads cloudflare network ranges
func DownloadLiveRanges(ctx context.Context, log *logrus.Logger) (string, error) {
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

// Checks if ip belongs to a cloudflare network.
func IpBelongsToCfNetwork(ranges []*net.IPNet, ip net.IP) bool {
	for _, cidr := range ranges {
		belongs := cidr.Contains(ip)
		if belongs {
			return true
		}
	}
	return false
}
