package httputil

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContentTypeFor(t *testing.T) {
	cases := []struct {
		format BodyFormat
		want   string
	}{
		{FormatJSON, "application/json"},
		{FormatForm, "application/x-www-form-urlencoded"},
		{FormatXML, "application/xml"},
		{FormatMultipart, "multipart/form-data; boundary=----CaidoBodyConvertBoundary"},
		{BodyFormat("nope"), ""},
	}
	for _, tc := range cases {
		if got := ContentTypeFor(tc.format); got != tc.want {
			t.Errorf("ContentTypeFor(%q) = %q, want %q", tc.format, got, tc.want)
		}
	}
}

func TestConvertBody_SameFormatUnchanged(t *testing.T) {
	body := `{"a":1}`
	got, ct, err := ConvertBody(body, FormatJSON, FormatJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != body {
		t.Errorf("body changed: got %q want %q", got, body)
	}
	if ct != "application/json" {
		t.Errorf("contentType = %q, want application/json", ct)
	}
}

func TestConvertBody_JSONToForm_Flat(t *testing.T) {
	got, ct, err := ConvertBody(`{"a":"1","b":"two"}`, FormatJSON, FormatForm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("contentType = %q", ct)
	}
	want := "a=1&b=two"
	if got != want {
		t.Errorf("form = %q, want %q", got, want)
	}
}

func TestConvertBody_JSONToForm_Nested(t *testing.T) {
	got, _, err := ConvertBody(`{"a":"1","b":{"c":"2"},"arr":["x"]}`, FormatJSON, FormatForm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Keys are sorted; brackets are url-escaped (%5B = [, %5D = ]).
	want := "a=1&arr%5B0%5D=x&b%5Bc%5D=2"
	if got != want {
		t.Errorf("nested form = %q, want %q", got, want)
	}
}

func TestConvertBody_FormToJSON_RoundTripFlat(t *testing.T) {
	form := "a=1&b=two"
	jsonOut, _, err := ConvertBody(form, FormatForm, FormatJSON)
	if err != nil {
		t.Fatalf("form->json error: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &m); err != nil {
		t.Fatalf("output not valid JSON object: %v (%s)", err, jsonOut)
	}
	if m["a"] != "1" || m["b"] != "two" {
		t.Errorf("round trip lost data: %#v", m)
	}
}

func TestConvertBody_JSONToMultipart_Fields(t *testing.T) {
	got, ct, err := ConvertBody(`{"a":"1","b":"two"}`, FormatJSON, FormatMultipart)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(ct, "multipart/form-data; boundary=----CaidoBodyConvertBoundary") {
		t.Errorf("contentType = %q", ct)
	}
	// Fixed boundary makes the output deterministic and assertable.
	checks := []string{
		"------CaidoBodyConvertBoundary",
		"Content-Disposition: form-data; name=\"a\"",
		"Content-Disposition: form-data; name=\"b\"",
		"------CaidoBodyConvertBoundary--",
	}
	for _, c := range checks {
		if !strings.Contains(got, c) {
			t.Errorf("multipart output missing %q\ngot:\n%s", c, got)
		}
	}
}

func TestConvertBody_MultipartToJSON_RoundTrip(t *testing.T) {
	mp, _, err := ConvertBody(`{"a":"1","b":"two"}`, FormatJSON, FormatMultipart)
	if err != nil {
		t.Fatalf("json->multipart error: %v", err)
	}
	jsonOut, _, err := ConvertBody(mp, FormatMultipart, FormatJSON)
	if err != nil {
		t.Fatalf("multipart->json error: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &m); err != nil {
		t.Fatalf("output not valid JSON object: %v (%s)", err, jsonOut)
	}
	if m["a"] != "1" || m["b"] != "two" {
		t.Errorf("multipart round trip lost data: %#v", m)
	}
}

func TestConvertBody_JSONToMultipart_RejectsNested(t *testing.T) {
	_, _, err := ConvertBody(`{"a":{"b":"c"}}`, FormatJSON, FormatMultipart)
	if err == nil {
		t.Fatal("expected error for nested multipart field, got nil")
	}
	if !strings.Contains(err.Error(), "scalar") {
		t.Errorf("error = %v, want mention of scalar", err)
	}
}

func TestConvertBody_JSONToMultipart_RejectsNonObject(t *testing.T) {
	_, _, err := ConvertBody(`["a","b"]`, FormatJSON, FormatMultipart)
	if err == nil {
		t.Fatal("expected error for non-object multipart source, got nil")
	}
}

func TestConvertBody_JSONToXML_Structural(t *testing.T) {
	got, ct, err := ConvertBody(
		`{"a":"1","items":["x","y"],"nested":{"k":"v"}}`, FormatJSON, FormatXML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/xml" {
		t.Errorf("contentType = %q", ct)
	}
	// Keys are emitted in sorted order; arrays repeat the element.
	want := "<root><a>1</a><items>x</items><items>y</items><nested><k>v</k></nested></root>"
	if got != want {
		t.Errorf("xml = %q, want %q", got, want)
	}
}

func TestConvertBody_XMLToJSON_Structural(t *testing.T) {
	xmlIn := "<root><a>1</a><items>x</items><items>y</items><nested><k>v</k></nested></root>"
	jsonOut, _, err := ConvertBody(xmlIn, FormatXML, FormatJSON)
	if err != nil {
		t.Fatalf("xml->json error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("output not valid JSON object: %v (%s)", err, jsonOut)
	}
	if got["a"] != "1" {
		t.Errorf("a = %v, want \"1\"", got["a"])
	}
	items, ok := got["items"].([]any)
	if !ok || len(items) != 2 || items[0] != "x" || items[1] != "y" {
		t.Errorf("items = %#v, want [x y]", got["items"])
	}
	nested, ok := got["nested"].(map[string]any)
	if !ok || nested["k"] != "v" {
		t.Errorf("nested = %#v, want {k:v}", got["nested"])
	}
}

func TestConvertBody_JSONToXML_RoundTrip(t *testing.T) {
	src := `{"a":"1","items":["x","y"],"nested":{"k":"v"}}`
	xmlOut, _, err := ConvertBody(src, FormatJSON, FormatXML)
	if err != nil {
		t.Fatalf("json->xml error: %v", err)
	}
	back, _, err := ConvertBody(xmlOut, FormatXML, FormatJSON)
	if err != nil {
		t.Fatalf("xml->json error: %v", err)
	}
	var want, got map[string]any
	if err := json.Unmarshal([]byte(src), &want); err != nil {
		t.Fatalf("seed invalid: %v", err)
	}
	if err := json.Unmarshal([]byte(back), &got); err != nil {
		t.Fatalf("round trip invalid: %v", err)
	}
	if got["a"] != want["a"] {
		t.Errorf("a mismatch: got %v want %v", got["a"], want["a"])
	}
}

func TestConvertBody_InvalidJSON(t *testing.T) {
	_, _, err := ConvertBody(`{not json`, FormatJSON, FormatForm)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("error = %v, want mention of valid JSON", err)
	}
}

func TestConvertBody_InvalidXML(t *testing.T) {
	_, _, err := ConvertBody(`<root><a></root>`, FormatXML, FormatJSON)
	if err == nil {
		t.Fatal("expected error for malformed XML, got nil")
	}
}

func TestConvertBody_InvalidMultipart(t *testing.T) {
	_, _, err := ConvertBody(`no boundary here`, FormatMultipart, FormatJSON)
	if err == nil {
		t.Fatal("expected error for missing multipart boundary, got nil")
	}
}

func TestConvertBody_UnsupportedFormats(t *testing.T) {
	if _, _, err := ConvertBody(`{}`, BodyFormat("yaml"), FormatJSON); err == nil {
		t.Error("expected error for unsupported source format")
	}
	if _, _, err := ConvertBody(`{}`, FormatJSON, BodyFormat("yaml")); err == nil {
		t.Error("expected error for unsupported target format")
	}
}

func TestIsKnownFormat(t *testing.T) {
	known := []BodyFormat{FormatJSON, FormatForm, FormatXML, FormatMultipart}
	for _, f := range known {
		if !IsKnownFormat(f) {
			t.Errorf("IsKnownFormat(%q) = false, want true", f)
		}
	}
	if IsKnownFormat(BodyFormat("csv")) {
		t.Error("IsKnownFormat(csv) = true, want false")
	}
}
