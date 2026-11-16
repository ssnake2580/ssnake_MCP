package httputil

import (
	"fmt"
	"net/url"
)

// DefaultPort returns the default TCP port for an HTTP(S) connection:
// 443 when TLS is used, 80 otherwise.
func DefaultPort(useTLS bool) int {
	if useTLS {
		return 443
	}
	return 80
}

// RequestURL synthesizes the *url.URL targeted by a raw HTTP request,
// used for RFC 6265 cookie matching against the session jar.
func RequestURL(host string, port int, useTLS bool, raw string) *url.URL {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	defaultPort := DefaultPort(useTLS)
	hostHeader := host
	if port != 0 && port != defaultPort {
		hostHeader = fmt.Sprintf("%s:%d", host, port)
	}
	target := ExtractPath(raw)
	u, err := url.Parse(scheme + "://" + hostHeader + target)
	if err != nil {
		return &url.URL{Scheme: scheme, Host: hostHeader, Path: "/"}
	}
	return u
}

func BuildURL(
	isTLS bool, host string, port int, path, query string,
) string {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s", scheme, host)
	if (isTLS && port != 443) || (!isTLS && port != 80) {
		u = fmt.Sprintf("%s:%d", u, port)
	}
	u += path
	if query != "" {
		u += "?" + query
	}
	return u
}
