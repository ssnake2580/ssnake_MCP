package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerFindingsResource(server *mcp.Server, client *caido.Client) {
	server.AddResource(
		&mcp.Resource{
			URI:         "caido://findings",
			Name:        "caido-findings",
			Description: "Security findings reported by Caido workflows and manual testing",
			MIMEType:    "text/plain",
		},
		findingsHandler(client),
	)
}

func findingsHandler(client *caido.Client) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		limit := 100
		resp, err := client.Findings.List(ctx, &caido.ListFindingsOptions{
			First: &limit,
		})
		if err != nil {
			return nil, fmt.Errorf("list findings: %w", err)
		}

		var b strings.Builder
		b.WriteString("# Security Findings\n\n")

		for _, edge := range resp.Findings.Edges {
			f := edge.Node
			ts := time.UnixMilli(f.CreatedAt).Format(time.RFC3339)
			fmt.Fprintf(&b, "## %s\n", f.Title)
			fmt.Fprintf(&b, "- ID: %s\n", f.Id)
			fmt.Fprintf(&b, "- Host: %s\n", f.Host)
			fmt.Fprintf(&b, "- Path: %s\n", f.Path)
			fmt.Fprintf(&b, "- Reporter: %s\n", f.Reporter)
			fmt.Fprintf(&b, "- Created: %s\n", ts)
			fmt.Fprintf(&b, "- Request: %s\n", f.Request.Id)
			if f.Description != nil {
				fmt.Fprintf(&b, "- Description: %s\n", *f.Description)
			}
			b.WriteString("\n")
		}

		if len(resp.Findings.Edges) == 0 {
			b.WriteString("(no findings recorded yet)\n")
		}

		if resp.Findings.PageInfo.HasNextPage {
			b.WriteString("... (more findings available, use caido_list_findings tool for pagination)\n")
		}

		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:  req.Params.URI,
				Text: b.String(),
			}},
		}, nil
	}
}
