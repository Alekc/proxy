package judge

import (
	"fmt"
	"net/http"
	"strings"
)

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
	"Content-AnonType":          nil,
	"Content-Length":            nil,
	"User-Agent":                nil,
	"Via":                       nil,
	"X-Forwarded-For":           nil,
	"X-Proxy-Id":                nil,
	"Dnt":                       nil,
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
