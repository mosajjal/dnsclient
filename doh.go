package dnsclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"net"
	"time"

	"net/http"
	"net/url"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

// DoHClient encapsulates all functions and attributes for a DoH client
type DoHClient struct {
	URL          url.URL
	proxy        string
	dialer       proxy.Dialer
	isSkipVerify bool
	req          *http.Request
	httpclient   *http.Client
	cache        *Cache
}

// NewDoHClient creates a new DoH client
func NewDoHClient(server url.URL, SkipVerify bool, proxy string) (Client, error) {
	// Select TLS protocols for DoH
	c := DoHClient{
		URL:          server,
		proxy:        proxy,
		isSkipVerify: SkipVerify,
		cache:        InitCache(),
	}

	// get the proxy dialer
	var err error
	c.dialer, err = GetDialer(proxy)
	if err != nil {
		return nil, err
	}

	c.httpclient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return c.dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: SkipVerify,
			},
		},
	}

	c.req, err = http.NewRequest(http.MethodGet, c.URL.String(), nil)
	return &c, err // nil error
}

// Query performs a DoH query
func (c DoHClient) Query(ctx context.Context, msg *dns.Msg) ([]dns.RR, time.Duration, error) {
	// get the time
	start := time.Now()

	// check the cache
	if c.cache != nil {
		if rr, ok := c.cache.Get(msg); ok {
			return rr, time.Since(start), nil
		}
	}

	dohbytes, err := msg.Pack()
	if err != nil {
		return []dns.RR{}, time.Since(start), err
	}
	// convert to base64
	dohbase64 := base64.RawURLEncoding.EncodeToString(dohbytes)

	q := c.req.URL.Query()
	q.Set("dns", dohbase64)
	c.req.URL.RawQuery = q.Encode()

	c.req = c.req.WithContext(ctx)
	res, err := c.httpclient.Do(c.req)
	if err != nil {
		return []dns.RR{}, time.Since(start), err
	}
	body, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	// read the body
	// parse body as a dns message
	var msg2 dns.Msg
	err = msg2.Unpack(body)
	return msg2.Answer, time.Since(start), err
}

func (c *DoHClient) Close() error {
	c.req.Close = true
	return nil
}
func (c *DoHClient) Reconnect() error {
	newClient, err := NewDoHClient(c.URL, c.isSkipVerify, c.proxy)
	c2 := newClient.(*DoHClient)
	c.req = c2.req
	return err
}
