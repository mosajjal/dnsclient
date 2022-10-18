package dnsclient

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"net/http"
	"net/http/httptrace"
	"net/url"

	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// Client encapsulates all functions and attributes for a DoH client
type DoHClient struct {
	Session *httptrace.ClientTrace
	URL     url.URL
}

// New creates a new DoH client
func NewDoHClient(server url.URL, SkipVerify bool) (Client, error) {
	// Select TLS protocols for DoH
	c := DoHClient{}
	// log.Debugln("dialing doh server")
	c.Session = &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {},
	}
	c.URL = server
	return c, nil // nil error
}

// SendQuery performs a DoH query
func (c DoHClient) Query(ctx context.Context, msg *dns.Msg) ([]dns.RR, time.Duration, error) {
	// get the time
	start := time.Now()
	msgbytes, err := msg.Pack()
	if err != nil {
		return []dns.RR{}, 0, err
	}

	m := dnsmessage.Message{}
	err = m.Unpack(msgbytes)
	if err != nil {
		return []dns.RR{}, 0, err
	}
	dohbytes, err := m.Pack()
	if err != nil {
		return []dns.RR{}, 0, err
	}
	// convert to base64
	dohbase64 := base64.StdEncoding.EncodeToString(dohbytes)
	dohbase64 = strings.TrimSuffix(dohbase64, "=")
	// and get the response
	traceCtx := httptrace.WithClientTrace(ctx, c.Session)

	dohURL := c.URL.Scheme + "://" + c.URL.Host + c.URL.Path + "?dns=" + dohbase64
	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, dohURL, nil)
	if err != nil {
		log.Println(err)
		return []dns.RR{}, 0, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return []dns.RR{}, 0, err
	}
	// read the body
	body, _ := ioutil.ReadAll(res.Body)
	// parse body as a dns message
	var msg2 dns.Msg
	err = msg2.Unpack(body)
	// return the message
	return msg2.Answer, time.Since(start), err
}
