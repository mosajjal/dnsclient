package dnsclient_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnsclient"
	"github.com/stretchr/testify/assert"
)

func TestTransportDoQ(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion("example.com.", dns.TypeA)

	u := "dns.adguard.com:8853"
	c, err := dnsclient.NewDoQClient(u, false)
	assert.Nil(t, err)
	defer c.Close()
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}

func BenchmarkTransportDoQ(b *testing.B) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion("example.com.", dns.TypeA)

	u := "dns.adguard.com:8853"
	c, _ := dnsclient.NewDoQClient(u, false)
	defer c.Close()
	for n := 0; n < b.N; n++ {
		c.Query(context.Background(), &msg)
	}
}
