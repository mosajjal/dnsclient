package dnsclient

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"time"

	"net/http"
	"net/url"

	"github.com/miekg/dns"
)

// DoHClient encapsulates all functions and attributes for a DoH client
type DoHClient struct {
	URL          url.URL
	isSkipVerify bool
	req          *http.Request
}

// NewDoHClient creates a new DoH client
func NewDoHClient(server url.URL, SkipVerify bool) (Client, error) {
	// Select TLS protocols for DoH
	c := DoHClient{
		URL: server,
	}
	c.isSkipVerify = SkipVerify

	var err error
	c.req, err = http.NewRequest(http.MethodGet, c.URL.String(), nil)
	return &c, err // nil error
}

// Query performs a DoH query
func (c DoHClient) Query(ctx context.Context, msg *dns.Msg) ([]dns.RR, time.Duration, error) {
	// get the time
	start := time.Now()
	dohbytes, err := msg.Pack()
	if err != nil {
		return []dns.RR{}, time.Since(start), err
	}
	// convert to base64
	dohbase64 := base64.StdEncoding.EncodeToString(dohbytes)
	dohbase64 = strings.TrimSuffix(dohbase64, "=")
	q := c.req.URL.Query()
	q.Set("dns", dohbase64)
	c.req.URL.RawQuery = q.Encode()

	c.req = c.req.WithContext(ctx)
	res, err := http.DefaultClient.Do(c.req)
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
	newClient, err := NewDoHClient(c.URL, c.isSkipVerify)
	c2 := newClient.(*DoHClient)
	c.req = c2.req
	return err
}
