package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromIpv4String(t *testing.T) {
	_, err := FromIpv4String("")
	assert.EqualError(t, err, "input string is empty", "empty address should return an error")

	for _, v := range []string{"260.1.1.1:123", "invalid string", "1.1.1.1:123456"} {
		_, err = FromIpv4String(v)
		assert.EqualError(t, err, "this is not a valid ipv4 address", "Address should be in a form of xxx.xxx.xxx.xxx:xxxxx")
	}

	_, err = FromIpv4String("1.2.3.4:66000")
	assert.EqualError(t, err, "invalid port", "port should be between 1 and 65535")

	px, err := FromIpv4String("1.2.3.4:567")
	assert.NoError(t, err, "ip shouldn't return an error")
	assert.Equal(t, &Proxy{"1.2.3.4", 567, 0}, px, "result unexpected")

}

func TestProxy_ToString(t *testing.T) {
	px := &Proxy{
		IP:   "1.2.3.4",
		Port: 1234,
	}
	assert.Equal(t, "1.2.3.4:1234", px.ToString(), "result should be 1.2.3.4:1234")
}
