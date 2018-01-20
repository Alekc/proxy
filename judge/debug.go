package judge

import (
	"fmt"
	"net/http"
	"strings"
)

var excludedHeaders = map[string]int{
	"Connection":                0,
	"Accept-Encoding":           0,
	"Cf-Ipcountry":              0,
	"Accept":                    0,
	"Accept-Language":           0,
	"Cf-Ray":                    0,
	"X-Forwarded-Proto":         0,
	"Upgrade-Insecure-Requests": 0,
	"Cache-Control":             0,
	"Cookie":                    0,
	"Cf-Connecting-Ip":          0,
	"Cf-Visitor":                0,
	"Content-Type":              0,
	"Content-Length":            0,
	"User-Agent":                0,
	"Via":                       0,
	"X-Forwarded-For":           0,
	"X-Proxy-Id":                0,
}

//author: https://medium.com/doing-things-right/pretty-printing-http-requests-in-golang-a918d5aaa000
// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	//httputil.DumpRequestOut(r, false)
	// Create return string
	var request []string

	request = append(request, "####################")

	// Add the request string
	//url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	//request = append(request, url)

	// Add the host
	//request = append(request, fmt.Sprintf("Host: %v", r.Host))

	// Loop through headers
	for name, headers := range r.Header {
		//remove header from debug if known.
		if _, ok := excludedHeaders[name]; ok {
			continue
		}
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}

	// Return the request as a string
	return strings.Join(request, "\n")
}
