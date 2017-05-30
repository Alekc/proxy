package tester

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

//Finds external ip. Relies on service given by api.ipify.org
//Returns an empty string in case it was impossible to obtain such
//information.
func GetRealIp() string {
	httpClient := &http.Client{
		Timeout: time.Second * 3,
	}
	//apify
	res, err := httpClient.Get("https://api.ipify.org")
	if err == nil && res.StatusCode == 200 {
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)
		return string(body)
	}
	//todo: add fallback
	return ""
}

//Checks if port is open or not
func CheckIfPortOpen(Host string, Port int, TimeOut time.Duration) bool {
	//configure timeout
	dialer := net.Dialer{Timeout: TimeOut}

	connectionString := fmt.Sprintf("%s:%d", Host, Port)

	//try to dial.
	conn, err := dialer.Dial("tcp", connectionString)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}
