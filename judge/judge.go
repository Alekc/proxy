package judge

import (
	"os"

	"github.com/alekc/proxy"
	"github.com/sirupsen/logrus"
)

const version = "0.1.0"

type Judge struct {
	ListenAddress string
	//Set to true if you want support for judge being behind the cloudflare infrastructure
	CloudFlareSupport bool
	//List of trusted gateways. If your judge instance is behind some load-balancer/gateway
	//which adds it's ip to x-forwarded-for header you might want to add it here.
	TrustedGatewaysIps []string
	logger             *logrus.Logger
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

func (j *Judge) SetLogger(log *logrus.Logger) {
	j.logger = log
}
func NewJudgement() *proxy.Judgement {
	return &proxy.Judgement{
		Messages: make([]string, 0),
	}
}
