// Package allowlist implements a default-deny domain and CIDR allowlist transform.
package allowlist

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts against
// domain globs and CIDR ranges.
type Allowlist struct {
	matcher *hostmatch.Matcher
}

type allowlistConfig struct {
	Domains []string `yaml:"domains"`
	CIDRs   []string `yaml:"cidrs"`
}

func factory(cfg yaml.Node) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return New(c.Domains, c.CIDRs, net.DefaultResolver)
}

// New creates an Allowlist from domain globs and CIDR strings.
func New(domains []string, cidrs []string, resolver hostmatch.Resolver) (*Allowlist, error) {
	m, err := hostmatch.New(domains, cidrs, resolver)
	if err != nil {
		return nil, err
	}
	return &Allowlist{matcher: m}, nil
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(ctx context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := hostmatch.StripPort(req.Host)

	if a.matcher.Matches(ctx, host) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
