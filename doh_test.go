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
	msg.SetQuestion("example.com.", dns.TypeA)

	u := "https://cloudflare-dns.com/dns-query"
	uri, _ := url.Parse(u)
	c, err := dnsclient.NewDoHClient(*uri, true)
	assert.Nil(t, err)
	defer c.Close()
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}

func BenchmarkTransportDoH(b *testing.B) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion("example.com.", dns.TypeA)

	u := "https://cloudflare-dns.com/dns-query"
	uri, _ := url.Parse(u)
	c, _ := dnsclient.NewDoHClient(*uri, true)
	defer c.Close()
	for n := 0; n < b.N; n++ {
		c.Query(context.Background(), &msg)
	}
}
