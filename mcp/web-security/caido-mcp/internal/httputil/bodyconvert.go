package httputil

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"mime/multipart"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// BodyFormat identifies a request/response body serialization format.
type BodyFormat string

// Supported body formats.
const (
	FormatJSON      BodyFormat = "json"
	FormatForm      BodyFormat = "form"
	FormatXML       BodyFormat = "xml"
	FormatMultipart BodyFormat = "multipart"
)

// multipartBoundary is a FIXED boundary so multipart output is deterministic
// and assertable in tests. Do NOT swap this for crypto/rand or a clock-based
// value -- nondeterministic boundaries break tests.
const multipartBoundary = "----CaidoBodyConvertBoundary"

// xmlRoot wraps converted JSON when emitting XML and is the element parsed
// when reading XML back into JSON.
const xmlRoot = "root"

// ContentTypeFor returns the HTTP Content-Type header value for a format.
// Multipart includes the fixed boundary parameter.
func ContentTypeFor(f BodyFormat) string {
	switch f {
	case FormatJSON:
		return "application/json"
	case FormatForm:
		return "application/x-www-form-urlencoded"
	case FormatXML:
		return "application/xml"
	case FormatMultipart:
		return "multipart/form-data; boundary=" + multipartBoundary
	default:
		return ""
	}
}

// IsKnownFormat reports whether f is one of the supported formats.
func IsKnownFormat(f BodyFormat) bool {
	switch f {
	case FormatJSON, FormatForm, FormatXML, FormatMultipart:
		return true
	default:
		return false
	}
}

// ConvertBody converts body from one format to another. When from == to the
// body is returned unchanged. The returned contentType matches the target
// format. Errors are returned for invalid input or unsupported directions.
func ConvertBody(body string, from, to BodyFormat) (string, string, error) {
	if !IsKnownFormat(from) {
		return "", "", fmt.Errorf("convert body: unsupported source format %q", from)
	}
	if !IsKnownFormat(to) {
		return "", "", fmt.Errorf("convert body: unsupported target format %q", to)
	}
	if from == to {
		return body, ContentTypeFor(to), nil
	}

	// All conversions route through a generic value (decoded from the source)
	// then encode into the target. This keeps the matrix linear.
	val, err := decodeBody(body, from)
	if err != nil {
		return "", "", err
	}
	out, err := encodeBody(val, to)
	if err != nil {
		return "", "", err
	}
	return out, ContentTypeFor(to), nil
}

// decodeBody parses a source body into a generic JSON-like value. For form and
// multipart the result is a flat map[string]any of string values.
func decodeBody(body string, from BodyFormat) (any, error) {
	switch from {
	case FormatJSON:
		return decodeJSON(body)
	case FormatForm:
		return decodeForm(body)
	case FormatXML:
		return decodeXML(body)
	case FormatMultipart:
		return decodeMultipart(body)
	default:
		return nil, fmt.Errorf("convert body: unsupported source format %q", from)
	}
}

// encodeBody serializes a generic value into the target format.
func encodeBody(val any, to BodyFormat) (string, error) {
	switch to {
	case FormatJSON:
		return encodeJSON(val)
	case FormatForm:
		return encodeForm(val)
	case FormatXML:
		return encodeXML(val)
	case FormatMultipart:
		return encodeMultipart(val)
	default:
		return "", fmt.Errorf("convert body: unsupported target format %q", to)
	}
}

func decodeJSON(body string) (any, error) {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil, fmt.Errorf("convert body: input is not valid JSON: %w", err)
	}
	return v, nil
}

func encodeJSON(val any) (string, error) {
	b, err := json.Marshal(val)
	if err != nil {
		return "", fmt.Errorf("convert body: failed to encode JSON: %w", err)
	}
	return string(b), nil
}

// decodeForm parses url-encoded data into a flat map. Nested reconstruction
// from bracket notation is best-effort/not attempted -- keys are kept verbatim
// (e.g. "a[b]"), and repeated keys keep the first value.
func decodeForm(body string) (any, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, fmt.Errorf("convert body: input is not valid form data: %w", err)
	}
	out := make(map[string]any, len(values))
	for k, vs := range values {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out, nil
}

// encodeForm flattens a JSON value into url-encoded form data. Nested objects
// use bracket notation (a[b]=c) and arrays use indices (a[0]=x). Output keys
// are sorted for deterministic results.
func encodeForm(val any) (string, error) {
	values := url.Values{}
	flattenJSON(val, "", values)
	return encodeValuesSorted(values), nil
}

// flattenJSON walks a decoded JSON value writing leaf scalars into values
// using bracket notation under prefix.
func flattenJSON(val any, prefix string, values url.Values) {
	switch t := val.(type) {
	case map[string]any:
		for k, v := range t {
			flattenJSON(v, joinKey(prefix, k), values)
		}
	case []any:
		for i, v := range t {
			flattenJSON(v, fmt.Sprintf("%s[%d]", prefix, i), values)
		}
	default:
		key := prefix
		if key == "" {
			key = "value"
		}
		values.Set(key, scalarString(val))
	}
}

func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return fmt.Sprintf("%s[%s]", prefix, key)
}

// encodeValuesSorted is like url.Values.Encode but emits keys in sorted order.
func encodeValuesSorted(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range values[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

func scalarString(val any) string {
	switch t := val.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// encodeXML wraps a JSON value in <root>...</root>. Objects become nested
// elements, arrays become repeated elements, and scalars become text.
func encodeXML(val any) (string, error) {
	var b strings.Builder
	writeXMLElement(&b, xmlRoot, val)
	return b.String(), nil
}

// writeXMLElement emits one element named tag containing val. Maps recurse
// with child element names from their keys (sorted for determinism); slices
// repeat tag once per item; scalars are escaped text.
func writeXMLElement(b *strings.Builder, tag string, val any) {
	switch t := val.(type) {
	case map[string]any:
		b.WriteString("<" + tag + ">")
		for _, k := range sortedKeys(t) {
			writeXMLElement(b, k, t[k])
		}
		b.WriteString("</" + tag + ">")
	case []any:
		for _, item := range t {
			writeXMLElement(b, tag, item)
		}
	default:
		b.WriteString("<" + tag + ">")
		b.WriteString(escapeXMLText(scalarString(val)))
		b.WriteString("</" + tag + ">")
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func escapeXMLText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// decodeXML parses XML into a generic map. The single root element is unwrapped
// so the returned value mirrors the original JSON object. Attributes are
// ignored. Repeated child element names collapse into arrays.
func decodeXML(body string) (any, error) {
	dec := xml.NewDecoder(strings.NewReader(body))
	node, err := parseXMLElement(dec)
	if err != nil {
		return nil, fmt.Errorf("convert body: input is not valid XML: %w", err)
	}
	if node == nil {
		return map[string]any{}, nil
	}
	return node.value, nil
}

// xmlNode is the parsed shape of an element: either child elements (children)
// or text content (text).
type xmlNode struct {
	value any
}

// parseXMLElement reads one start element (the root) and returns its value.
// It expects the decoder positioned before the root start token.
func parseXMLElement(dec *xml.Decoder) (*xmlNode, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			v, err := parseXMLContent(dec, start)
			if err != nil {
				return nil, err
			}
			return &xmlNode{value: v}, nil
		}
	}
}

// parseXMLContent consumes tokens until the matching end element of start,
// returning either a string (text-only) or map[string]any (child elements).
func parseXMLContent(dec *xml.Decoder, start xml.StartElement) (any, error) {
	children := map[string]any{}
	var text strings.Builder
	hasChild := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			hasChild = true
			v, err := parseXMLContent(dec, t)
			if err != nil {
				return nil, err
			}
			addXMLChild(children, t.Name.Local, v)
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if hasChild {
				return children, nil
			}
			return strings.TrimSpace(text.String()), nil
		}
	}
}

// addXMLChild inserts value under key, promoting to a slice when the key
// repeats (so multiple same-named elements become a JSON array).
func addXMLChild(children map[string]any, key string, value any) {
	existing, ok := children[key]
	if !ok {
		children[key] = value
		return
	}
	if arr, isArr := existing.([]any); isArr {
		children[key] = append(arr, value)
		return
	}
	children[key] = []any{existing, value}
}

// encodeMultipart serializes a flat JSON object into multipart/form-data using
// the fixed boundary. Only flat string fields are supported (no files); nested
// values are rejected with a clear error.
func encodeMultipart(val any) (string, error) {
	obj, ok := val.(map[string]any)
	if !ok {
		return "", fmt.Errorf(
			"convert body: multipart target requires a flat JSON object")
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(multipartBoundary); err != nil {
		return "", fmt.Errorf("convert body: failed to set multipart boundary: %w", err)
	}
	for _, k := range sortedKeys(obj) {
		if !isScalar(obj[k]) {
			return "", fmt.Errorf(
				"convert body: multipart field %q is not a scalar "+
					"(nested objects/arrays unsupported)", k)
		}
		if err := w.WriteField(k, scalarString(obj[k])); err != nil {
			return "", fmt.Errorf("convert body: failed to write multipart field %q: %w", k, err)
		}
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("convert body: failed to finalize multipart body: %w", err)
	}
	return buf.String(), nil
}

func isScalar(val any) bool {
	switch val.(type) {
	case map[string]any, []any:
		return false
	default:
		return true
	}
}

// decodeMultipart parses a multipart/form-data body (using the fixed boundary)
// into a flat map of string fields. File parts are ignored.
func decodeMultipart(body string) (any, error) {
	boundary, err := multipartBoundaryFrom(body)
	if err != nil {
		return nil, err
	}
	r := multipart.NewReader(strings.NewReader(body), boundary)
	form, err := r.ReadForm(int64(len(body)) + 1024)
	if err != nil {
		return nil, fmt.Errorf("convert body: input is not valid multipart data: %w", err)
	}
	defer func() { _ = form.RemoveAll() }()
	out := make(map[string]any, len(form.Value))
	for k, vs := range form.Value {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out, nil
}

// multipartBoundaryFrom derives the boundary from the body's first delimiter
// line. It accepts the fixed boundary directly, falling back to parsing the
// leading "--<boundary>" so externally produced bodies still decode.
func multipartBoundaryFrom(body string) (string, error) {
	trimmed := strings.TrimLeft(body, "\r\n")
	if !strings.HasPrefix(trimmed, "--") {
		return "", fmt.Errorf(
			"convert body: input is not valid multipart data: missing boundary")
	}
	line := trimmed
	if idx := strings.IndexAny(trimmed, "\r\n"); idx >= 0 {
		line = trimmed[:idx]
	}
	boundary := strings.TrimPrefix(line, "--")
	if boundary == "" {
		return "", fmt.Errorf(
			"convert body: input is not valid multipart data: empty boundary")
	}
	return boundary, nil
}
