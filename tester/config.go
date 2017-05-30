package tester

import "time"

const version = "0.1"

const (
	TYPE_UNKNOWN = iota
	TYPE_HTTP
	TYPE_HTTPS
	TYPE_SOCKS4
	TYPE_SOCKS5
)

var DefaultConfig Config

type Config struct {
	ConnectTimeout  time.Duration
	DownloadTimeout time.Duration
	UserAgent       string
	HttpUri         string
	HttpsUri        string
}

func init() {
	opt := Config{}
	opt.ConnectTimeout = time.Second * 3
	opt.DownloadTimeout = time.Second * 5
	//opt.UserAgent = "ProxyTester - " + version
	opt.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0"
	opt.HttpUri = "http://judge.px.alekc.org/"
	opt.HttpsUri = "https://judge.px.alekc.org/"

	DefaultConfig = opt
}