package dnsclient_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnsclient"
	"github.com/stretchr/testify/assert"
)

func TestTransportDoH(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	u := "https://cloudflare-dns.com/dns-query"
	uri, _ := url.Parse(u)
	c, err := dnsclient.NewDoHClient(*uri, true)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}
