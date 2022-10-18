package dnsclient

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
	doqclient "github.com/mosajjal/doqd/pkg/client"
)

// Client encapsulates all functions and attributes for a DoH client
type DoQClient struct {
	Client doqclient.Client
}

// New creates a new DoQ client
func NewDoQClient(server string, SkipVerify bool) (Client, error) {
	doqClient, err := doqclient.New(server, SkipVerify, true)

	return DoQClient{Client: doqClient}, err
}

func (c DoQClient) Query(ctx context.Context, msg *dns.Msg) (responses []dns.RR, rtt time.Duration, err error) {
	//TODO: implement context
	t1 := time.Now()

	fnDone := make(chan bool)
	go func() {
		var r dns.Msg
		r, err = c.Client.SendQuery(*msg)
		responses = r.Answer
		rtt = time.Since(t1)
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
