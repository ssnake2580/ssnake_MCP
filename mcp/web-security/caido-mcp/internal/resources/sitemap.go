package resources

import (
	"context"
	"fmt"
	"strings"

	caido "github.com/caido-community/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSitemapResource(server *mcp.Server, client *caido.Client) {
	server.AddResource(
		&mcp.Resource{
			URI:         "caido://sitemap",
			Name:        "caido-sitemap",
			Description: "Root domains from Caido sitemap",
			MIMEType:    "text/plain",
		},
		sitemapHandler(client),
	)
}

func sitemapHandler(client *caido.Client) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		resp, err := client.Sitemap.ListRootEntries(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list sitemap roots: %w", err)
		}

		var b strings.Builder
		b.WriteString("# Sitemap - Root Domains\n\n")

		for _, edge := range resp.SitemapRootEntries.Edges {
			e := edge.Node
			fmt.Fprintf(&b, "- %s (id: %s, kind: %s", e.Label, e.Id, string(e.Kind))
			if e.HasDescendants {
				b.WriteString(", has children")
			}
			b.WriteString(")\n")
		}

		if len(resp.SitemapRootEntries.Edges) == 0 {
			b.WriteString("(empty - no requests captured yet)\n")
		}

		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:  req.Params.URI,
				Text: b.String(),
			}},
		}, nil
	}
}
