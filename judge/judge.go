package judge

const version = "0.1.0"

type Judge struct {
	ListenAddress string
	//Set to true if you want support for judge being behind the cloudflare infrastructure
	CloudFlareSupport bool
	//List of trusted gateways. If your judge instance is behind some load-balancer/gateway
	//which adds it's ip to x-forwarded-for header you might want to add it here.
	TrustedGatewaysIps []string
	//If you want some debug messages
	DebugEnabled bool
}

//Create new Judge instance
func Create() *Judge {
	obj := new(Judge)
	obj.ListenAddress = ":8080"
	obj.CloudFlareSupport = true
	return obj
}
