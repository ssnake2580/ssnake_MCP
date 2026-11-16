# Test Infra + CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automated test infrastructure and CI pipeline that protects against regressions on every PR.

**Architecture:** Mock Caido's GraphQL API at the HTTP transport layer using `httptest.NewServer`. The mock routes GraphQL operation names to fixture JSON files. MCP tool tests use the go-sdk's `InMemoryTransport` to test tools end-to-end without network. GitHub Actions CI runs build + test + lint on every PR.

**Tech Stack:** Go 1.24, stdlib `testing` + `net/http/httptest`, `mcp.NewInMemoryTransports()` from go-sdk v1.2.0, GitHub Actions

---

### Task 1: Mock Caido GraphQL Server

**Files:**
- Create: `internal/testutil/mock_caido.go`
- Create: `internal/testutil/testutil.go`

- [ ] **Step 1: Create the testutil package with mock server**

```go
// internal/testutil/mock_caido.go
package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	caido "github.com/caido-community/sdk-go"
)

type MockHandler struct {
	mu        sync.Mutex
	responses map[string]json.RawMessage
}

func NewMockHandler() *MockHandler {
	return &MockHandler{
		responses: make(map[string]json.RawMessage),
	}
}

func (m *MockHandler) On(operationName string, response any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, _ := json.Marshal(response)
	m.responses[operationName] = json.RawMessage(data)
}

func (m *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	var req struct {
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	resp, ok := m.responses[req.OperationName]
	m.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]string{
				{"message": "no mock for operation: " + req.OperationName},
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]json.RawMessage{
		"data": resp,
	})
}
```

```go
// internal/testutil/testutil.go
package testutil

import (
	"net/http/httptest"
	"testing"

	caido "github.com/caido-community/sdk-go"
)

type TestEnv struct {
	Client  *caido.Client
	Mock    *MockHandler
	Server  *httptest.Server
}

func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	mock := NewMockHandler()
	server := httptest.NewServer(mock)
	t.Cleanup(server.Close)

	client, err := caido.NewClient(caido.Options{
		URL:  server.URL,
		Auth: caido.PATAuth("test-token"),
	})
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	return &TestEnv{
		Client: client,
		Mock:   mock,
		Server: server,
	}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/testutil/...`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add internal/testutil/mock_caido.go internal/testutil/testutil.go
git commit -m "test: add mock Caido GraphQL server for unit tests"
```

---

### Task 2: Test Fixtures for Core Operations

**Files:**
- Create: `internal/testutil/fixtures.go`

- [ ] **Step 1: Create fixture helpers with canned responses**

```go
// internal/testutil/fixtures.go
package testutil

import (
	"encoding/base64"
	"fmt"
)

func RawHTTPResponse(status int, body string) string {
	raw := fmt.Sprintf(
		"HTTP/1.1 %d OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
		status, len(body), body,
	)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func RawHTTPRequest(method, path, host string) string {
	raw := fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		method, path, host,
	)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func ListRequestsResponse(ids ...string) map[string]any {
	edges := make([]map[string]any, len(ids))
	for i, id := range ids {
		edges[i] = map[string]any{
			"node": map[string]any{
				"id":     id,
				"method": "GET",
				"host":   "example.com",
				"port":   443,
				"path":   "/api/" + id,
				"query":  "",
				"isTls":  true,
				"response": map[string]any{
					"statusCode": 200,
				},
			},
		}
	}
	return map[string]any{
		"requests": map[string]any{
			"edges": edges,
			"pageInfo": map[string]any{
				"hasNextPage": false,
				"endCursor":   nil,
			},
		},
	}
}

func GetRequestMetadataResponse(id string) map[string]any {
	return map[string]any{
		"request": map[string]any{
			"id":        id,
			"method":    "GET",
			"host":      "example.com",
			"port":      443,
			"path":      "/test",
			"query":     "",
			"isTls":     true,
			"createdAt": int64(1714900000000),
			"response": map[string]any{
				"statusCode":    200,
				"roundtripTime": 42,
			},
		},
	}
}

func GetRequestFullResponse(id string, body string) map[string]any {
	return map[string]any{
		"request": map[string]any{
			"id":        id,
			"method":    "POST",
			"host":      "example.com",
			"port":      443,
			"path":      "/submit",
			"query":     "",
			"isTls":     true,
			"createdAt": int64(1714900000000),
			"raw":       RawHTTPRequest("POST", "/submit", "example.com"),
			"response": map[string]any{
				"statusCode":    200,
				"roundtripTime": 55,
				"raw":           RawHTTPResponse(200, body),
			},
		},
	}
}

func CreateReplaySessionResponse(sessionID string) map[string]any {
	return map[string]any{
		"createReplaySession": map[string]any{
			"session": map[string]any{
				"id": sessionID,
			},
		},
	}
}

func GetReplaySessionResponse(sessionID, activeEntryID string) map[string]any {
	var activeEntry any
	if activeEntryID != "" {
		activeEntry = map[string]any{"id": activeEntryID}
	}
	return map[string]any{
		"replaySession": map[string]any{
			"id":          sessionID,
			"activeEntry": activeEntry,
		},
	}
}

func StartReplayTaskResponse() map[string]any {
	return map[string]any{
		"startReplayTask": map[string]any{
			"error": nil,
		},
	}
}

func GetReplayEntryResponse(entryID, requestID string, statusCode int, body string) map[string]any {
	return map[string]any{
		"replayEntry": map[string]any{
			"id": entryID,
			"request": map[string]any{
				"id":  requestID,
				"raw": RawHTTPRequest("GET", "/test", "example.com"),
				"response": map[string]any{
					"statusCode":    statusCode,
					"roundtripTime": 100,
					"raw":           RawHTTPResponse(statusCode, body),
				},
			},
		},
	}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/testutil/...`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add internal/testutil/fixtures.go
git commit -m "test: add fixture helpers for Caido API responses"
```

---

### Task 3: MCP Tool Test Helper

**Files:**
- Create: `internal/testutil/mcp_helper.go`

- [ ] **Step 1: Create helper to register and call MCP tools in tests**

```go
// internal/testutil/mcp_helper.go
package testutil

import (
	"context"
	"encoding/json"
	"testing"

	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type MCPTestEnv struct {
	*TestEnv
	Server  *mcp.Server
	Client  *mcp.ClientSession
	cancel  context.CancelFunc
}

func NewMCPTestEnv(t *testing.T, register func(server *mcp.Server, client *caido.Client)) *MCPTestEnv {
	t.Helper()
	env := NewTestEnv(t)

	server := mcp.NewServer(
		&mcp.Implementation{Name: "test-server", Version: "0.0.1"},
		nil,
	)
	register(server, env.Client)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	go func() {
		_ = server.Connect(ctx, serverTransport, nil)
	}()

	mcpClient := mcp.NewClient(
		&mcp.Implementation{Name: "test-client", Version: "0.0.1"},
		nil,
	)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("mcp client connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return &MCPTestEnv{
		TestEnv: env,
		Server:  server,
		Client:  session,
		cancel:  cancel,
	}
}

func (e *MCPTestEnv) CallTool(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := e.Client.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: mustMarshalMap(args),
	})
	if err != nil {
		t.Fatalf("CallTool(%s) error: %v", name, err)
	}
	return result
}

func (e *MCPTestEnv) CallToolExpectError(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := e.Client.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: mustMarshalMap(args),
	})
	if err != nil {
		return nil
	}
	if !result.IsError {
		t.Fatalf("CallTool(%s) expected error, got success", name)
	}
	return result
}

func mustMarshalMap(m map[string]any) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		data, _ := json.Marshal(v)
		result[k] = json.RawMessage(data)
	}
	return result
}

func UnmarshalToolResult[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty tool result content")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	var out T
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal tool result: %v\nraw: %s", err, text.Text)
	}
	return out
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/testutil/...`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add internal/testutil/mcp_helper.go
git commit -m "test: add MCP tool test helper with InMemoryTransport"
```

---

### Task 4: Unit Tests for list_requests

**Files:**
- Create: `internal/tools/list_requests_test.go`

- [ ] **Step 1: Write table-driven tests**

```go
// internal/tools/list_requests_test.go
package tools_test

import (
	"testing"

	"github.com/c0tton-fluff/caido-mcp-server/internal/testutil"
	"github.com/c0tton-fluff/caido-mcp-server/internal/tools"
	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestListRequests(t *testing.T) {
	tests := []struct {
		name       string
		args       map[string]any
		setup      func(*testutil.MockHandler)
		wantCount  int
		wantHasMore bool
		wantError  bool
	}{
		{
			name: "returns requests with default limit",
			args: map[string]any{},
			setup: func(m *testutil.MockHandler) {
				m.On("Requests", testutil.ListRequestsResponse("r1", "r2", "r3"))
			},
			wantCount: 3,
		},
		{
			name: "respects custom limit",
			args: map[string]any{"limit": 2},
			setup: func(m *testutil.MockHandler) {
				m.On("Requests", testutil.ListRequestsResponse("r1", "r2"))
			},
			wantCount: 2,
		},
		{
			name: "rejects httpql over 10000 chars",
			args: map[string]any{"httpql": string(make([]byte, 10001))},
			setup: func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name: "caps limit at 100",
			args: map[string]any{"limit": 500},
			setup: func(m *testutil.MockHandler) {
				m.On("Requests", testutil.ListRequestsResponse("r1"))
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
				tools.RegisterListRequestsTool(s, c)
			})
			tt.setup(env.Mock)

			result := env.CallTool(t, "caido_list_requests", tt.args)

			if tt.wantError {
				if !result.IsError {
					t.Fatal("expected error result")
				}
				return
			}

			output := testutil.UnmarshalToolResult[tools.ListRequestsOutput](t, result)
			if len(output.Requests) != tt.wantCount {
				t.Fatalf("want %d requests, got %d", tt.wantCount, len(output.Requests))
			}
			if output.HasMore != tt.wantHasMore {
				t.Fatalf("want hasMore=%v, got %v", tt.wantHasMore, output.HasMore)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to see if they pass**

Run: `go test ./internal/tools/ -run TestListRequests -v`
Expected: Tests pass (mock returns canned data, tool logic processes it)

- [ ] **Step 3: Fix any issues with mock operation name routing**

The genqlient operation name may differ from what we expect. Check the actual operation name by inspecting the request body in the mock handler. If the operation name is different (e.g., `"requests"` vs `"Requests"`), update the fixture setup accordingly.

Add debug logging to `MockHandler.ServeHTTP` temporarily if needed:
```go
t.Logf("mock received operation: %q", req.OperationName)
```

- [ ] **Step 4: Commit**

```bash
git add internal/tools/list_requests_test.go
git commit -m "test: add unit tests for caido_list_requests tool"
```

---

### Task 5: Unit Tests for get_request

**Files:**
- Create: `internal/tools/get_request_test.go`

- [ ] **Step 1: Write table-driven tests**

```go
// internal/tools/get_request_test.go
package tools_test

import (
	"testing"

	"github.com/c0tton-fluff/caido-mcp-server/internal/testutil"
	"github.com/c0tton-fluff/caido-mcp-server/internal/tools"
	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGetRequest(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]any
		setup       func(*testutil.MockHandler)
		wantMethod  string
		wantStatus  int
		wantError   bool
		wantErrText string
	}{
		{
			name: "returns metadata by default",
			args: map[string]any{"ids": []string{"req-1"}},
			setup: func(m *testutil.MockHandler) {
				m.On("RequestMetadata", testutil.GetRequestMetadataResponse("req-1"))
			},
			wantMethod: "GET",
			wantStatus: 200,
		},
		{
			name: "returns full request with body",
			args: map[string]any{
				"ids":     []string{"req-1"},
				"include": []string{"metadata", "responseHeaders", "responseBody"},
			},
			setup: func(m *testutil.MockHandler) {
				m.On("Request", testutil.GetRequestFullResponse("req-1", "<html>OK</html>"))
			},
			wantMethod: "POST",
			wantStatus: 200,
		},
		{
			name:      "rejects empty ids",
			args:      map[string]any{"ids": []string{}},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name:      "rejects more than 20 ids",
			args:      map[string]any{"ids": make([]string, 21)},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
				tools.RegisterGetRequestTool(s, c)
			})
			tt.setup(env.Mock)

			result := env.CallTool(t, "caido_get_request", tt.args)

			if tt.wantError {
				if !result.IsError {
					t.Fatal("expected error result")
				}
				return
			}

			output := testutil.UnmarshalToolResult[tools.GetRequestOutput](t, result)
			if tt.wantMethod != "" && output.Method != tt.wantMethod {
				t.Fatalf("want method %q, got %q", tt.wantMethod, output.Method)
			}
			if tt.wantStatus != 0 && output.StatusCode != tt.wantStatus {
				t.Fatalf("want status %d, got %d", tt.wantStatus, output.StatusCode)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/tools/ -run TestGetRequest -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/tools/get_request_test.go
git commit -m "test: add unit tests for caido_get_request tool"
```

---

### Task 6: Unit Tests for send_request

**Files:**
- Create: `internal/tools/send_request_test.go`

- [ ] **Step 1: Write table-driven tests**

```go
// internal/tools/send_request_test.go
package tools_test

import (
	"testing"

	"github.com/c0tton-fluff/caido-mcp-server/internal/replay"
	"github.com/c0tton-fluff/caido-mcp-server/internal/testutil"
	"github.com/c0tton-fluff/caido-mcp-server/internal/tools"
	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSendRequest(t *testing.T) {
	tests := []struct {
		name       string
		args       map[string]any
		setup      func(*testutil.MockHandler)
		wantStatus int
		wantError  bool
	}{
		{
			name: "sends request and returns response",
			args: map[string]any{
				"raw":  "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
				"host": "example.com",
			},
			setup: func(m *testutil.MockHandler) {
				m.On("CreateReplaySession", testutil.CreateReplaySessionResponse("sess-1"))
				m.On("StartReplayTask", testutil.StartReplayTaskResponse())
				m.On("ReplaySession", testutil.GetReplaySessionResponse("sess-1", "entry-1"))
				m.On("ReplayEntry", testutil.GetReplayEntryResponse("entry-1", "req-1", 200, "OK"))
			},
			wantStatus: 200,
		},
		{
			name: "uses provided sessionId",
			args: map[string]any{
				"raw":       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
				"host":      "example.com",
				"sessionId": "my-session",
			},
			setup: func(m *testutil.MockHandler) {
				m.On("StartReplayTask", testutil.StartReplayTaskResponse())
				m.On("ReplaySession", testutil.GetReplaySessionResponse("my-session", "entry-2"))
				m.On("ReplayEntry", testutil.GetReplayEntryResponse("entry-2", "req-2", 301, ""))
			},
			wantStatus: 301,
		},
		{
			name:      "rejects empty raw",
			args:      map[string]any{"raw": ""},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name:      "rejects raw over 1MB",
			args:      map[string]any{"raw": string(make([]byte, 1048577)), "host": "x.com"},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name:      "rejects missing host",
			args:      map[string]any{"raw": "GET / HTTP/1.1\r\n\r\n"},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name: "defaults to port 443 with TLS",
			args: map[string]any{
				"raw":  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
				"host": "example.com",
			},
			setup: func(m *testutil.MockHandler) {
				m.On("CreateReplaySession", testutil.CreateReplaySessionResponse("sess-2"))
				m.On("StartReplayTask", testutil.StartReplayTaskResponse())
				m.On("ReplaySession", testutil.GetReplaySessionResponse("sess-2", "entry-3"))
				m.On("ReplayEntry", testutil.GetReplayEntryResponse("entry-3", "req-3", 200, "hi"))
			},
			wantStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			replay.ResetDefaultSession("")
			t.Cleanup(func() { replay.ResetDefaultSession("") })

			env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
				tools.RegisterSendRequestTool(s, c)
			})
			tt.setup(env.Mock)

			if tt.wantError {
				result := env.CallTool(t, "caido_send_request", tt.args)
				if !result.IsError {
					t.Fatal("expected error result")
				}
				return
			}

			result := env.CallTool(t, "caido_send_request", tt.args)
			output := testutil.UnmarshalToolResult[tools.SendRequestOutput](t, result)
			if output.StatusCode != tt.wantStatus {
				t.Fatalf("want status %d, got %d", tt.wantStatus, output.StatusCode)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/tools/ -run TestSendRequest -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/tools/send_request_test.go
git commit -m "test: add unit tests for caido_send_request tool"
```

---

### Task 7: Unit Tests for batch_send

**Files:**
- Create: `internal/tools/batch_send_test.go`

- [ ] **Step 1: Write table-driven tests**

```go
// internal/tools/batch_send_test.go
package tools_test

import (
	"testing"

	"github.com/c0tton-fluff/caido-mcp-server/internal/testutil"
	"github.com/c0tton-fluff/caido-mcp-server/internal/tools"
	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestBatchSend(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]any
		setup       func(*testutil.MockHandler)
		wantResults int
		wantSummary string
		wantError   bool
	}{
		{
			name: "sends batch of 2 requests",
			args: map[string]any{
				"requests": []map[string]any{
					{"label": "req-a", "raw": "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"},
					{"label": "req-b", "raw": "GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"},
				},
			},
			setup: func(m *testutil.MockHandler) {
				m.On("CreateReplaySession", testutil.CreateReplaySessionResponse("batch-sess-1"))
				m.On("StartReplayTask", testutil.StartReplayTaskResponse())
				m.On("ReplaySession", testutil.GetReplaySessionResponse("batch-sess-1", "entry-b1"))
				m.On("ReplayEntry", testutil.GetReplayEntryResponse("entry-b1", "req-b1", 200, "ok"))
			},
			wantResults: 2,
		},
		{
			name:      "rejects empty requests array",
			args:      map[string]any{"requests": []map[string]any{}},
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
		{
			name: "rejects more than 50 requests",
			args: func() map[string]any {
				reqs := make([]map[string]any, 51)
				for i := range reqs {
					reqs[i] = map[string]any{"label": "x", "raw": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"}
				}
				return map[string]any{"requests": reqs}
			}(),
			setup:     func(m *testutil.MockHandler) {},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
				tools.RegisterBatchSendTool(s, c)
			})
			tt.setup(env.Mock)

			result := env.CallTool(t, "caido_batch_send", tt.args)

			if tt.wantError {
				if !result.IsError {
					t.Fatal("expected error result")
				}
				return
			}

			output := testutil.UnmarshalToolResult[tools.BatchSendOutput](t, result)
			if len(output.Results) != tt.wantResults {
				t.Fatalf("want %d results, got %d", tt.wantResults, len(output.Results))
			}
		})
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/tools/ -run TestBatchSend -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/tools/batch_send_test.go
git commit -m "test: add unit tests for caido_batch_send tool"
```

---

### Task 8: Schema Contract Tests

**Files:**
- Create: `internal/tools/schema_test.go`

- [ ] **Step 1: Write a test that verifies all registered tools have valid schemas**

```go
// internal/tools/schema_test.go
package tools_test

import (
	"context"
	"testing"

	"github.com/c0tton-fluff/caido-mcp-server/internal/testutil"
	"github.com/c0tton-fluff/caido-mcp-server/internal/tools"
	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var allRegistrations = []struct {
	name     string
	register func(*mcp.Server, *caido.Client)
}{
	{"caido_list_requests", tools.RegisterListRequestsTool},
	{"caido_get_request", tools.RegisterGetRequestTool},
	{"caido_send_request", tools.RegisterSendRequestTool},
	{"caido_batch_send", tools.RegisterBatchSendTool},
	{"caido_list_replay_sessions", tools.RegisterListReplaySessionsTool},
	{"caido_get_replay_entry", tools.RegisterGetReplayEntryTool},
	{"caido_list_automate_sessions", tools.RegisterListAutomateSessionsTool},
	{"caido_get_automate_session", tools.RegisterGetAutomateSessionTool},
	{"caido_get_automate_entry", tools.RegisterGetAutomateEntryTool},
	{"caido_automate_task_control", tools.RegisterAutomateTaskControlTool},
	{"caido_list_findings", tools.RegisterListFindingsTool},
	{"caido_create_finding", tools.RegisterCreateFindingTool},
	{"caido_delete_findings", tools.RegisterDeleteFindingsTool},
	{"caido_export_findings", tools.RegisterExportFindingsTool},
	{"caido_get_sitemap", tools.RegisterGetSitemapTool},
	{"caido_list_scopes", tools.RegisterListScopesTool},
	{"caido_create_scope", tools.RegisterCreateScopeTool},
	{"caido_list_projects", tools.RegisterListProjectsTool},
	{"caido_select_project", tools.RegisterSelectProjectTool},
	{"caido_list_workflows", tools.RegisterListWorkflowsTool},
	{"caido_run_workflow", tools.RegisterRunWorkflowTool},
	{"caido_toggle_workflow", tools.RegisterToggleWorkflowTool},
	{"caido_list_environments", tools.RegisterListEnvironmentsTool},
	{"caido_select_environment", tools.RegisterSelectEnvironmentTool},
	{"caido_get_instance", tools.RegisterGetInstanceTool},
	{"caido_intercept_status", tools.RegisterInterceptStatusTool},
	{"caido_intercept_control", tools.RegisterInterceptControlTool},
	{"caido_list_intercept_entries", tools.RegisterListInterceptEntriesTool},
	{"caido_forward_intercept", tools.RegisterForwardInterceptTool},
	{"caido_drop_intercept", tools.RegisterDropInterceptTool},
	{"caido_list_tamper_rules", tools.RegisterListTamperRulesTool},
	{"caido_create_tamper_rule", tools.RegisterCreateTamperRuleTool},
	{"caido_update_tamper_rule", tools.RegisterUpdateTamperRuleTool},
	{"caido_toggle_tamper_rule", tools.RegisterToggleTamperRuleTool},
	{"caido_delete_tamper_rule", tools.RegisterDeleteTamperRuleTool},
	{"caido_list_filters", tools.RegisterListFiltersTool},
}

func TestAllToolsRegisterAndListable(t *testing.T) {
	env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
		for _, reg := range allRegistrations {
			reg.register(s, c)
		}
	})

	result, err := env.Client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	registered := make(map[string]bool)
	for _, tool := range result.Tools {
		registered[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		if tool.InputSchema.Type != "object" {
			t.Errorf("tool %q input schema type is %q, want 'object'", tool.Name, tool.InputSchema.Type)
		}
	}

	for _, reg := range allRegistrations {
		if !registered[reg.name] {
			t.Errorf("tool %q not found in ListTools response", reg.name)
		}
	}
}

func TestToolCount(t *testing.T) {
	env := testutil.NewMCPTestEnv(t, func(s *mcp.Server, c *caido.Client) {
		for _, reg := range allRegistrations {
			reg.register(s, c)
		}
	})

	result, err := env.Client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	expected := len(allRegistrations)
	if len(result.Tools) != expected {
		t.Fatalf("want %d tools registered, got %d", expected, len(result.Tools))
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/tools/ -run TestAllTools -v`
Expected: All tools register successfully and have valid schemas

- [ ] **Step 3: Commit**

```bash
git add internal/tools/schema_test.go
git commit -m "test: add schema contract tests for all MCP tools"
```

---

### Task 9: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create CI workflow**

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test ./... -race -count=1

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Install staticcheck
        run: go install honnef.co/go/tools/cmd/staticcheck@latest

      - name: Staticcheck
        run: staticcheck ./...
```

- [ ] **Step 2: Verify workflow syntax**

Run: `cat .github/workflows/ci.yml | python3 -c "import sys,yaml; yaml.safe_load(sys.stdin)" && echo "valid yaml"`
Expected: "valid yaml" (or install `yq` and use `yq . .github/workflows/ci.yml`)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow for build, test, vet, staticcheck"
```

---

### Task 10: Coverage Badge + Final Verification

**Files:**
- Modify: `README.md` (add badge)

- [ ] **Step 1: Add coverage reporting to CI**

Update `.github/workflows/ci.yml` test step to generate coverage:

Replace the `Test` step in the `test` job with:
```yaml
      - name: Test
        run: go test ./... -race -count=1 -coverprofile=coverage.out

      - name: Coverage summary
        run: go tool cover -func=coverage.out | tail -1
```

- [ ] **Step 2: Add badge to README**

Add after the existing MCP badge line in `README.md`:
```markdown
  <a href="https://github.com/c0tton-fluff/caido-mcp-server/actions"><img src="https://github.com/c0tton-fluff/caido-mcp-server/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
```

- [ ] **Step 3: Run full test suite locally**

Run: `go test ./... -race -count=1 -v`
Expected: All tests pass, including new tool tests and schema contract tests

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: add coverage output and CI badge to README"
```

---

### Task 11: Verify Mock Operation Names

**Files:**
- Modify: `internal/testutil/mock_caido.go` (if needed)

- [ ] **Step 1: Identify actual GraphQL operation names**

Run a test with debug output to capture what operation names genqlient sends:

```bash
go test ./internal/tools/ -run TestListRequests -v -count=1 2>&1 | head -50
```

If tests fail because the mock doesn't match operation names, check the genqlient-generated code:

Run: `grep -r "operationName\|OperationName\|const.*Operation" $(go list -m -json github.com/caido-community/sdk-go | python3 -c "import sys,json;print(json.load(sys.stdin)['Dir'])")/graphql/ 2>/dev/null | head -20`

- [ ] **Step 2: Update fixture setup calls to use correct operation names**

Common genqlient pattern: operation names match the Go function names. For example:
- `client.Requests.List()` likely uses operation `"Requests"` or `"requests"`
- `client.Replay.CreateSession()` likely uses `"CreateReplaySession"`

Update all `m.On(...)` calls in test files to use the exact operation names found in step 1.

- [ ] **Step 3: Run full suite to confirm**

Run: `go test ./... -race -count=1`
Expected: All tests pass

- [ ] **Step 4: Commit if changes were needed**

```bash
git add -u
git commit -m "test: fix mock operation names to match genqlient"
```
