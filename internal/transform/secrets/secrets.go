// Package secrets implements a transform that swaps proxy tokens for real
// secrets on outbound requests, scoped to allowed hosts.
package secrets

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const defaultBodyMaxBytes int64 = 1 << 20 // 1MB

func init() {
	transform.Register("secrets", factory)
}

// secretsConfig is the YAML config structure.
type secretsConfig struct {
	Source  string        `yaml:"source"`
	Secrets []secretEntry `yaml:"secrets"`
}

type secretEntry struct {
	Var          string      `yaml:"var"`
	ProxyValue   string      `yaml:"proxy_value"`
	MatchHeaders []string    `yaml:"match_headers"`
	MatchBody    bool        `yaml:"match_body"`
	Hosts        []hostMatch `yaml:"hosts"`
}

type hostMatch struct {
	Name string `yaml:"name,omitempty"`
	CIDR string `yaml:"cidr,omitempty"`
}

// resolvedSecret is a secret ready for use after config parsing and env lookup.
type resolvedSecret struct {
	name         string // env var name, for logging/metrics
	proxyValue   string
	realValue    string
	matchHeaders []string // empty = all headers
	matchBody    bool
	matcher      *hostmatch.Matcher
}

// Secrets is the transform that swaps proxy tokens for real secrets.
type Secrets struct {
	secrets []resolvedSecret
}

// envLookup is the function used to read environment variables.
// Overridable in tests.
var envLookup = os.Getenv

func factory(cfg yaml.Node) (transform.Transformer, error) {
	var c secretsConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	return newFromConfig(c, envLookup)
}

// newFromConfig creates a Secrets transform from a parsed config, using the
// given env lookup function. Exported-via-test only.
func newFromConfig(cfg secretsConfig, getenv func(string) string) (*Secrets, error) {
	if cfg.Source != "env" {
		return nil, fmt.Errorf("unsupported secrets source: %q (only \"env\" is supported)", cfg.Source)
	}

	resolved := make([]resolvedSecret, 0, len(cfg.Secrets))
	for i, entry := range cfg.Secrets {
		if entry.ProxyValue == "" {
			return nil, fmt.Errorf("secrets[%d] (%s): proxy_value is required", i, entry.Var)
		}

		realValue := getenv(entry.Var)
		if realValue == "" {
			return nil, fmt.Errorf("secrets[%d]: env var %q is not set or empty", i, entry.Var)
		}

		var domains []string
		var cidrs []string
		for _, h := range entry.Hosts {
			if h.Name != "" {
				domains = append(domains, h.Name)
			}
			if h.CIDR != "" {
				cidrs = append(cidrs, h.CIDR)
			}
		}

		// Host matching doesn't need DNS resolution for the secrets transform —
		// we only match against the request Host header, not resolved IPs,
		// unless CIDRs are configured.
		matcher, err := hostmatch.New(domains, cidrs, hostmatch.NullResolver{})
		if err != nil {
			return nil, fmt.Errorf("secrets[%d] (%s): %w", i, entry.Var, err)
		}

		resolved = append(resolved, resolvedSecret{
			name:         entry.Var,
			proxyValue:   entry.ProxyValue,
			realValue:    realValue,
			matchHeaders: entry.MatchHeaders,
			matchBody:    entry.MatchBody,
			matcher:      matcher,
		})
	}

	return &Secrets{secrets: resolved}, nil
}

func (s *Secrets) Name() string { return "secrets" }

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := hostmatch.StripPort(req.Host)

	type swapRecord struct {
		Secret    string   `json:"secret"`
		Locations []string `json:"locations"`
	}
	var swapped []swapRecord

	for _, sec := range s.secrets {
		if !sec.matcher.Matches(ctx, host) {
			continue
		}

		var locations []string
		locations = append(locations, s.swapHeaders(req, &sec)...)
		locations = append(locations, s.swapQuery(req, &sec)...)

		if sec.matchBody {
			if loc := s.swapBody(req, &sec); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			swapped = append(swapped, swapRecord{Secret: sec.name, Locations: locations})
		}
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) swapHeaders(req *http.Request, sec *resolvedSecret) []string {
	var locations []string
	if len(sec.matchHeaders) > 0 {
		for _, name := range sec.matchHeaders {
			if vals := req.Header.Values(name); len(vals) > 0 {
				for _, v := range vals {
					if strings.Contains(v, sec.proxyValue) {
						locations = append(locations, "header:"+name)
						break
					}
				}
				req.Header.Del(name)
				for _, v := range vals {
					req.Header.Add(name, strings.ReplaceAll(v, sec.proxyValue, sec.realValue))
				}
			}
		}
	} else {
		for name, vals := range req.Header {
			for i, v := range vals {
				if strings.Contains(v, sec.proxyValue) {
					req.Header[name][i] = strings.ReplaceAll(v, sec.proxyValue, sec.realValue)
					locations = append(locations, "header:"+name)
				}
			}
		}
	}
	return locations
}

func (s *Secrets) swapQuery(req *http.Request, sec *resolvedSecret) []string {
	raw := req.URL.RawQuery
	if raw == "" || !strings.Contains(raw, sec.proxyValue) {
		return nil
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}

	var locations []string
	for key, vals := range params {
		for i, v := range vals {
			if strings.Contains(v, sec.proxyValue) {
				params[key][i] = strings.ReplaceAll(v, sec.proxyValue, sec.realValue)
				locations = append(locations, "query:"+key)
			}
		}
	}

	if len(locations) > 0 {
		req.URL.RawQuery = params.Encode()
	}
	return locations
}

func (s *Secrets) swapBody(req *http.Request, sec *resolvedSecret) string {
	if req.Body == nil {
		return ""
	}

	rb, ok := req.Body.(*transform.ReplayableBody)
	if !ok {
		return ""
	}

	if err := rb.Buffer(defaultBodyMaxBytes); err != nil {
		return ""
	}

	data, err := io.ReadAll(rb)
	if err != nil {
		return ""
	}

	if !bytes.Contains(data, []byte(sec.proxyValue)) {
		_, _ = rb.Seek(0, io.SeekStart)
		return ""
	}

	replaced := bytes.ReplaceAll(data, []byte(sec.proxyValue), []byte(sec.realValue))
	req.Body = io.NopCloser(bytes.NewReader(replaced))
	req.ContentLength = int64(len(replaced))
	return "body"
}
