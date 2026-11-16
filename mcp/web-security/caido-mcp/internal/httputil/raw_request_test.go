package httputil

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtractPath_Common(t *testing.T) {
	cases := map[string]string{
		"GET /admin?id=1 HTTP/1.1\r\nHost: x\r\n\r\n":  "/admin?id=1",
		"POST /api/v2 HTTP/1.1\r\nHost: x\r\n\r\nbody": "/api/v2",
		"GET /\r\nHost: x": "/",
		"":                 "/",
		"BROKEN":           "/",
	}
	for raw, want := range cases {
		if got := ExtractPath(raw); got != want {
			t.Errorf("ExtractPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestHasHeader_CaseInsensitive(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nX-Foo: y\r\n\r\nbody"
	for _, name := range []string{"cookie", "Cookie", "COOKIE"} {
		if !HasHeader(raw, name) {
			t.Errorf("HasHeader(%q) = false, want true", name)
		}
	}
	if HasHeader(raw, "Authorization") {
		t.Errorf("HasHeader(Authorization) = true, want false")
	}
}

func TestHasHeader_BodyContentIgnored(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: x\r\n\r\nCookie: in-body=true"
	if HasHeader(raw, "Cookie") {
		t.Errorf("HasHeader should ignore body content")
	}
}

func TestInjectHeader_PreservesBody(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\ndata"
	out := InjectHeader(raw, "Cookie", "auth=token")

	if !strings.Contains(out, "\r\nCookie: auth=token\r\n") {
		t.Fatalf("injected header missing: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\ndata") {
		t.Fatalf("body should remain intact: %q", out)
	}
	if !HasHeader(out, "Cookie") {
		t.Fatalf("HasHeader should now report Cookie present")
	}
}

func TestInjectHeader_NoHeaderTerminator(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: x"
	out := InjectHeader(raw, "Cookie", "k=v")
	if !strings.Contains(out, "Cookie: k=v") {
		t.Errorf("expected injection even without terminator: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Errorf("expected terminator appended: %q", out)
	}
}

func TestExtractRawSetCookies_Basic(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Set-Cookie: session=abc; Path=/\r\n" +
		"Set-Cookie: csrf=xyz; HttpOnly; Path=/\r\n" +
		"Content-Length: 0\r\n\r\n")

	cookies := ExtractRawSetCookies(raw)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d: %#v", len(cookies), cookies)
	}
	gotNames := []string{cookies[0].Name, cookies[1].Name}
	want := map[string]bool{"session": true, "csrf": true}
	for _, n := range gotNames {
		if !want[n] {
			t.Errorf("unexpected cookie name: %s", n)
		}
	}
}

func TestExtractRawSetCookies_NoCookies(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if got := ExtractRawSetCookies(raw); len(got) != 0 {
		t.Errorf("expected 0 cookies, got %#v", got)
	}
}

func TestBuildCookieHeader(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "a", Value: "1"},
		{Name: "b", Value: "2"},
		{Name: "", Value: "skip"},
		nil,
	}
	got := BuildCookieHeader(cookies)
	if got != "a=1; b=2" {
		t.Errorf("got %q, want %q", got, "a=1; b=2")
	}
	if BuildCookieHeader(nil) != "" {
		t.Errorf("nil slice should return empty string")
	}
}
