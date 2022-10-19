package dnsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ClassicDNS provides functionality to create DNS over UDP, DNS over TCP and DNS over TLS
type ClassicDNS struct {
	conn net.Conn
}

// NewClassicDNS provides a client interface which you can query on
func NewClassicDNS(server net.Addr, UseTCP bool, UseTLS bool, SkipVerify bool) (Client, error) {

	classic := ClassicDNS{}
	var err error

	if UseTLS && !UseTCP {
		err = fmt.Errorf("can't use DNS over TLS without TCP")
		return classic, err
	}

	if UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: SkipVerify,
		}
		classic.conn, err = tls.Dial(server.Network(), server.String(), tlsCfg)
		return classic, err
	}

	if UseTCP {
		var s *net.TCPAddr
		if s, err = net.ResolveTCPAddr(server.Network(), server.String()); err == nil {
			classic.conn, err = net.DialTCP(server.Network(), nil, s)
		}
		return classic, err
	}

	var s *net.UDPAddr
	if s, err = net.ResolveUDPAddr(server.Network(), server.String()); err == nil {
		classic.conn, err = net.DialUDP(server.Network(), nil, s)
	}
	return classic, err
}

// Query takes a dns message and returns a list of resources
func (c ClassicDNS) Query(ctx context.Context, q *dns.Msg) (responses []dns.RR, rtt time.Duration, err error) {
	t1 := time.Now()
	fnDone := make(chan bool)
	go func() {
		co := &dns.Conn{Conn: c.conn}
		if err = co.WriteMsg(q); err != nil {
			fnDone <- true
		}
		var r *dns.Msg
		r, err = co.ReadMsg()
		// co.Close()
		if err == nil {
			if r.Truncated {
				err = fmt.Errorf("response was truncated. consider using a different protocol (TCP) for large queries")
			} else if r.Id == q.Id {
				responses = r.Answer
			} else {
				err = fmt.Errorf("%d", r.Id)
			}
		}
		fnDone <- true
	}()
	for {
		select {
		case <-fnDone:
			rtt = time.Since(t1)
			return
		case <-ctx.Done():
			rtt = time.Since(t1)
			err = fmt.Errorf("request timed out")
			return
		}
	}
}
