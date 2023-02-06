package dnsclient

import (
	"net/url"

	"golang.org/x/net/proxy"
)

func GetDialer(socksURL string) (proxy.Dialer, error) {
	if socksURL == "" {
		return proxy.Direct, nil
	}

	uri, err := url.Parse(socksURL)
	if err != nil {
		return proxy.Direct, err
	}

	return proxy.FromURL(uri, proxy.Direct)

}
