// Package dnsclient provides a minimal DNS client library. It provides native support for
// - Dns Over UDP
// - DNS Over TCP
// - DNS Over HTTPS (DoH)
// - DNS Over TLS (DoT)
// - DNS Over QUIC (DoQ)
package dnsclient

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

type Client interface {
	Query(context.Context, *dns.Msg) ([]dns.RR, time.Duration, error)
}

// New creates a DNS Client by parsing a URI and returning the appropriate client for it
// URI string could look like below:
// udp://1.1.1.1:53
// udp6://[2606:4700:4700::1111]:53
// tcp://9.9.9.9:5353
// https://dns.adguard.com
// quic://dns.adguard.com:8853
// tls://dns.adguard.com:853
func New(uri string, skipVerify bool) (Client, error) {
	parsedUrl, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	switch parsedUrl.Scheme {
	case "udp", "udp6":
		addr, err := net.ResolveUDPAddr(parsedUrl.Scheme, parsedUrl.Host)
		if err != nil {
			return nil, err
		}
		return NewClassicDNS(addr, false, false, skipVerify)
	case "tcp", "tcp6", "tls", "tls6":
		useTLS := false
		if parsedUrl.Scheme == "tls" || parsedUrl.Scheme == "tls6" {
			useTLS = true
		}
		addr, err := net.ResolveTCPAddr(parsedUrl.Scheme, parsedUrl.Host)
		if err != nil {
			return nil, err
		}
		return NewClassicDNS(addr, true, useTLS, skipVerify)
	case "https":
		return NewDoHClient(*parsedUrl, skipVerify)
	case "quic":
		return NewDoQClient(parsedUrl.Host, skipVerify)
	}
	return nil, fmt.Errorf("Can't understand the URL")
}
