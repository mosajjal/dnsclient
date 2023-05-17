package dnsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQClient encapsulates all functions and attributes for a DoH client
type DoQClient struct {
	conn         quic.Connection
	isSkipVerify bool
	server       string
	cache        *Cache
}

// NewDoQClient creates a new DoQ client
func NewDoQClient(server string, SkipVerify bool) (Client, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: SkipVerify,
		NextProtos:         []string{"doq"},
	}

	session, err := quic.DialAddr(server, &tlsConfig, &quic.Config{
		HandshakeIdleTimeout:    time.Second * 10,
		DisablePathMTUDiscovery: true,
	})

	if err != nil {
		return nil, fmt.Errorf("opening quic session to %s: %v", server, err)
	}

	// Clients and servers MUST NOT send the edns-tcp-keepalive EDNS(0) Option [RFC7828] in any messages sent
	// on a DoQ connection (because it is specific to the use of TCP/TLS as a transport).
	// https://datatracker.ietf.org/doc/html/rfc9250#section-5.5.2
	return &DoQClient{conn: session, server: server, isSkipVerify: SkipVerify, cache: InitCache()}, nil
}

// Query performs the DNS transaction
func (c DoQClient) Query(ctx context.Context, msg *dns.Msg) (responses []dns.RR, rtt time.Duration, err error) {
	t1 := time.Now()

	// check cache
	if c.cache != nil {
		if rr, ok := c.cache.Get(msg); ok {
			return rr, time.Since(t1), nil
		}
	}

	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = c.conn.CloseWithError(0x02, "") // Already closing the connection, so we don't care about the error
				return nil, time.Since(t1), fmt.Errorf("EDNS0 TCP keepalive option is set")
			}
		}
	}

	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, time.Since(t1), fmt.Errorf("open new stream to %s: %v", c.server, err)
	}
	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to zero.  The stream mapping for DoQ allows for unambiguous
	// correlation of queries and responses and so the Message ID field is
	// not required.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	msg.Id = 0
	buf, err := msg.Pack()
	if err != nil {
		return nil, time.Since(t1), err
	}

	_, err = stream.Write(buf)
	if err != nil {
		return nil, time.Since(t1), err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
	_ = stream.Close()

	respBuf, err := io.ReadAll(stream)
	if err != nil {
		return nil, time.Since(t1), fmt.Errorf("reading response from %s: %s", c.server, err)
	}
	if len(respBuf) == 0 {
		return nil, time.Since(t1), fmt.Errorf("empty response from %s", c.server)
	}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf)
	if err != nil {
		return nil, time.Since(t1), fmt.Errorf("unpacking response from %s: %s", c.server, err)
	}

	return reply.Answer, time.Since(t1), nil
}

func (c *DoQClient) Close() error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(2), "")
}
func (c *DoQClient) Reconnect() error {
	newClient, err := NewDoQClient(c.server, c.isSkipVerify)
	c2 := newClient.(*DoQClient)
	c.conn = c2.conn
	return err
}
