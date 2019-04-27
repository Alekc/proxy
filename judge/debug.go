package judge

import (
	"net/http"
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
	"Content-Type":              nil,
	"Content-Length":            nil,
	"User-Agent":                nil,
	"Via":                       nil,
	"X-Forwarded-For":           nil,
	"X-Proxy-Id":                nil,
	"Dnt":                       nil,
}

// author: https://medium.com/doing-things-right/pretty-printing-http-requests-in-golang-a918d5aaa000
// logRequest generates ascii representation of a request
func (j *Judge) logRequest(r *http.Request) {
	// Loop through headers
	for name, headers := range r.Header {
		//remove header from debug if it's known.
		if _, ok := excludedHeaders[name]; ok {
			continue
		}
		for _, h := range headers {
			j.logger.
				WithField("header_key", name).
				WithField("header_value", h).
				Warn("unknown header")
			//headerStrings = append(headerStrings, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		_ = r.ParseForm()
		j.logger.
			WithField("form_contents", r.Form.Encode()).
			Debug("Form present")
	}
}
