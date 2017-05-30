package tester

import (
	"github.com/alekc/socks"
	"net/http"
	"net/url"
	"fmt"
	"io/ioutil"
	"strings"
)

func TestHttp(Host string, Port int) (*Result, error) {
	return DefaultTester.TestHttp(Host, Port)
}
func (self *Tester) TestHttp(Host string, Port int) (*Result, error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s:%d", Host, Port))
	if err != nil {
		return nil, err
	}
	nProxy := http.ProxyURL(proxyUrl)
	
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nProxy}}
	result := self.downloadWithTransport(httpClient, DefaultConfig.HttpUri)
	
	return result, nil
}

func TestSocks4(Host string, Port int) (*Result) {
	return DefaultTester.TestSocks4(Host, Port)
}
func (self *Tester) TestSocks4(Host string, Port int) (*Result) {
	return self.testSocks(Host, Port, socks.SOCKS4)
}
func TestSocks5(Host string, Port int) (*Result) {
	return DefaultTester.TestSocks5(Host, Port)
}
func (self *Tester) TestSocks5(Host string, Port int) (*Result) {
	return self.testSocks(Host, Port, socks.SOCKS5)
}

func (self *Tester) testSocks(Host string, Port, socksType int) *Result {
	connectionString := fmt.Sprintf("%s:%s", Host, Port)
	
	//get the transport
	dialSocksProxy := socks.DialSocksProxy(socksType, connectionString)
	
	//link transport with httpClient
	transport := &http.Transport{Dial: dialSocksProxy}
	httpClient := &http.Client{Transport: transport}
	
	return self.downloadWithTransport(httpClient, DefaultConfig.HttpUri)
}

//execute download from given source
func (self *Tester) downloadWithTransport(httpClient *http.Client, uri string) *Result {
	result := new(Result)
	
	//If we do not know our real ip then return it
	if self.RealIp == "" {
		self.RealIp = GetRealIp()
	}
	
	//set timeout
	httpClient.Timeout = DefaultConfig.DownloadTimeout
	
	form := url.Values{}
	form.Add("real-ip", self.RealIp)
	
	//get request
	req, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		result.Err = err
		return result
	}
	req.Close = true
	
	//add custom headers
	req.Header.Add("User-Agent", DefaultConfig.UserAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	
	//let's try to fetch data
	resp, err := httpClient.Do(req)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()
	
	//define result
	result.ResponseCode = resp.StatusCode
	if resp.StatusCode != 200 {
		//backend error? our issue?
	}
	
	//try to get the body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Err = err
		return result
	}
	result.Body = string(body)
	result.Ok = true
	
	return result
}
