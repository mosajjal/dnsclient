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

// Client Provides a unified interface for DNS queries
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
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	switch parsedURL.Scheme {
	case "udp", "udp6":
		addr, err := net.ResolveUDPAddr(parsedURL.Scheme, parsedURL.Host)
		if err != nil {
			return nil, err
		}
		return NewClassicDNS(addr, false, false, skipVerify)
	case "tcp", "tcp6", "tls", "tls6":
		useTLS := false
		if parsedURL.Scheme == "tls" || parsedURL.Scheme == "tls6" {
			useTLS = true
		}
		addr, err := net.ResolveTCPAddr(parsedURL.Scheme, parsedURL.Host)
		if err != nil {
			return nil, err
		}
		return NewClassicDNS(addr, true, useTLS, skipVerify)
	case "https":
		return NewDoHClient(*parsedURL, skipVerify)
	case "quic":
		return NewDoQClient(parsedURL.Host, skipVerify)
	}
	return nil, fmt.Errorf("Can't understand the URL")
}
