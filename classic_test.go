package dnsclient_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnsclient"
	"github.com/stretchr/testify/assert"
)

func TestTransportPlainUDP(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	addr := &net.UDPAddr{
		IP:   net.IPv4(9, 9, 9, 9),
		Port: 53,
	}
	c, err := dnsclient.NewClassicDNS(addr, false, false, false)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
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
		IP:   net.IPv4(9, 9, 9, 9),
		Port: 53,
	}
	c, err := dnsclient.NewClassicDNS(addr, true, false, false)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
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
		IP:   net.IPv4(9, 9, 9, 9),
		Port: 853,
	}
	c, err := dnsclient.NewClassicDNS(addr, true, true, true)
	assert.Nil(t, err)
	reply, _, err := c.Query(context.Background(), &msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply), 0)
}
