package dnsclient_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnsclient"
	"github.com/stretchr/testify/assert"
)

var dnsServer = net.IPv4(1, 1, 1, 1)

func TestTransportPlainUDP(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.UDPAddr{
		IP:   dnsServer,
		Port: 53,
	}
	c, err := dnsclient.NewClassicDNS(addr, false, false, false)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}

func BenchmarkTransportPlainUDP(b *testing.B) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.UDPAddr{
		IP:   dnsServer,
		Port: 53,
	}
	c, _ := dnsclient.NewClassicDNS(addr, false, false, false)
	for n := 0; n < b.N; n++ {
		c.Query(context.Background(), &msg)
	}
}

func TestTransportPlainTCP(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.TCPAddr{
		IP:   dnsServer,
		Port: 53,
	}
	c, err := dnsclient.NewClassicDNS(addr, true, false, false)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}

func BenchmarkTransportPlainTCP(b *testing.B) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.TCPAddr{
		IP:   dnsServer,
		Port: 53,
	}
	c, _ := dnsclient.NewClassicDNS(addr, true, false, false)
	for n := 0; n < b.N; n++ {
		c.Query(context.Background(), &msg)
	}
}

func TestTransportTLS(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.TCPAddr{
		IP:   dnsServer,
		Port: 853,
	}
	c, err := dnsclient.NewClassicDNS(addr, true, true, true)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}

func BenchmarkTransportTLS(b *testing.B) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.TCPAddr{
		IP:   dnsServer,
		Port: 853,
	}
	c, _ := dnsclient.NewClassicDNS(addr, true, true, true)
	for n := 0; n < b.N; n++ {
		c.Query(context.Background(), &msg)
	}
}
