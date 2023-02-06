package dnsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

// ClassicDNS provides functionality to create DNS over UDP, DNS over TCP and DNS over TLS
type ClassicDNS struct {
	dialer       proxy.Dialer
	conn         net.Conn
	proxy        string
	isTCP        bool
	isTLS        bool
	isSkipVerify bool
}

// NewClassicDNS provides a client interface which you can query on
func NewClassicDNS(server net.Addr, UseTCP bool, UseTLS bool, SkipVerify bool, proxy string) (Client, error) {

	classic := ClassicDNS{
		isTCP:        UseTCP,
		isTLS:        UseTLS,
		isSkipVerify: SkipVerify,
		proxy:        proxy,
	}
	var err error

	// due to the implementation limitation (https://github.com/golang/go/issues/32790)
	// UDP will not work behind a proxy
	var s *net.UDPAddr
	if s, err = net.ResolveUDPAddr(server.Network(), server.String()); err == nil {
		classic.conn, err = net.DialUDP(server.Network(), nil, s)
		return &classic, err
	}

	classic.dialer, err = GetDialer(proxy)
	if err != nil {
		return &classic, err
	}
	proxiedConnection, err := classic.dialer.Dial(server.Network(), server.String())
	if err != nil {
		return &classic, err
	}

	if classic.isTLS && !classic.isTCP {
		err = fmt.Errorf("can't use DNS over TLS without TCP")
		return &classic, err
	}

	if classic.isTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: SkipVerify,
		}

		classic.conn = tls.Client(proxiedConnection, tlsCfg)
		return &classic, nil
	}

	// TCP
	classic.conn = proxiedConnection
	return &classic, err

}

// Query takes a dns message and returns a list of resources
func (c *ClassicDNS) Query(ctx context.Context, q *dns.Msg) (responses []dns.RR, rtt time.Duration, err error) {
	t1 := time.Now()
	fnDone := make(chan bool)

	go func() {
		co := &dns.Conn{Conn: c.conn}
		if err = co.WriteMsg(q); err != nil {
			fnDone <- true
		}
		var r *dns.Msg
		r, err = co.ReadMsg()
		if err == nil {
			if r.Truncated {
				err = fmt.Errorf("response for query %d was truncated. consider using a different protocol (TCP) for large queries", r.Id)
			} else if r.Id != q.Id {
				err = fmt.Errorf("query id (%d) and response id (%d) mismatch", q.Id, r.Id)
			} else {
				responses = r.Answer
			}
		} else if err == io.EOF {
			// auto-reconnect on connection failure
			// NOTE: potentially a chance to make this a configurable item
			// wait for a random number of milliseconds before reconnecting
			time.Sleep(time.Duration(1000+rand.Intn(1000)) * time.Millisecond)
			c.Reconnect()
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

// Close closes the DNS Client
func (c *ClassicDNS) Close() error {
	return c.conn.Close()
}

// Reconnect reads the configuration from the running instance, and tries to replace the client
// with a fresh connection on-the-fly
func (c *ClassicDNS) Reconnect() error {
	newClient, err := NewClassicDNS(c.conn.RemoteAddr(), c.isTCP, c.isTLS, c.isSkipVerify, c.proxy)
	if err != nil {
		return err
	}
	c2 := newClient.(*ClassicDNS)
	c.conn = c2.conn
	return nil
}
