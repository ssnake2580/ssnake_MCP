package httputil

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// ExtractPath returns the request-target from the start-line of a raw
// HTTP request. Returns "/" when the start-line cannot be parsed.
func ExtractPath(raw string) string {
	idx := strings.Index(raw, "\n")
	if idx < 0 {
		return "/"
	}
	startLine := strings.TrimSpace(raw[:idx])
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) < 2 {
		return "/"
	}
	target := parts[1]
	if target == "" {
		return "/"
	}
	return target
}

// HasHeader reports whether the raw request contains the named header.
// Comparison is case-insensitive. Body content is not searched.
func HasHeader(raw, name string) bool {
	lowerName := strings.ToLower(name)
	headerEnd := strings.Index(raw, "\r\n\r\n")
	if headerEnd < 0 {
		headerEnd = len(raw)
	}
	prefix := lowerName + ":"
	for line := range strings.SplitSeq(raw[:headerEnd], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return true
		}
	}
	return false
}

// InjectHeader appends a header line at the end of the header block
// of a raw HTTP request, preserving body and CRLF terminator. The raw
// input must already be CRLF-normalized via NormalizeCRLF.
func InjectHeader(raw, name, value string) string {
	separator := "\r\n\r\n"
	idx := strings.Index(raw, separator)
	if idx < 0 {
		return raw + "\r\n" + name + ": " + value + separator
	}
	headers := raw[:idx]
	rest := raw[idx:]
	return headers + "\r\n" + name + ": " + value + rest
}

// ExtractRawSetCookies parses the raw HTTP response and returns
// http.Cookie pointers from every Set-Cookie header. Returns an empty
// slice when none are present or the response cannot be parsed.
func ExtractRawSetCookies(rawResponse []byte) []*http.Cookie {
	parts := bytes.SplitN(rawResponse, []byte("\r\n\r\n"), 2)
	if len(parts) == 0 {
		return nil
	}
	headerBlock := parts[0]

	reader := bufio.NewReader(bytes.NewReader(headerBlock))
	if _, err := reader.ReadString('\n'); err != nil && err != io.EOF {
		return nil
	}

	header := http.Header{}
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" {
			if colon := strings.Index(trimmed, ":"); colon > 0 {
				key := strings.TrimSpace(trimmed[:colon])
				val := strings.TrimSpace(trimmed[colon+1:])
				header.Add(key, val)
			}
		}
		if err != nil {
			break
		}
	}

	resp := &http.Response{Header: header}
	return resp.Cookies()
}

// BuildCookieHeader returns a single Cookie header value built from
// cookies. Pairs are joined with "; ". Returns an empty string when
// the slice is empty.
func BuildCookieHeader(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	return strings.Join(pairs, "; ")
}
