package allowlist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type mockResolver struct {
	hosts map[string][]string
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addrs, ok := m.hosts[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func result(t *testing.T, a *Allowlist, host string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

func TestAllowlist_ExactDomainMatch(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WildcardDomain(t *testing.T) {
	a, err := New([]string{"*.anthropic.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "docs.api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "anthropic.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "notanthropic.com").Action)
}

func TestAllowlist_HostWithPort(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com:443").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com:443").Action)
}

func TestAllowlist_CIDRMatch(t *testing.T) {
	resolver := &mockResolver{
		hosts: map[string][]string{
			"internal.service": {"10.0.1.5"},
			"external.service": {"8.8.8.8"},
		},
	}
	a, err := New(nil, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "internal.service").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "external.service").Action)
}

func TestAllowlist_MultipleCIDRs(t *testing.T) {
	resolver := &mockResolver{
		hosts: map[string][]string{
			"a": {"10.0.0.1"},
			"b": {"172.16.0.1"},
			"c": {"8.8.8.8"},
		},
	}
	a, err := New(nil, []string{"10.0.0.0/8", "172.16.0.0/12"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "c").Action)
}

func TestAllowlist_DomainMatchSkipsCIDR(t *testing.T) {
	// If domain matches, CIDR check is not needed (even if resolver would fail)
	resolver := &mockResolver{} // no hosts — would fail lookup
	a, err := New([]string{"allowed.com"}, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "allowed.com").Action)
}

func TestAllowlist_UnresolvableHostDenied(t *testing.T) {
	resolver := &mockResolver{} // no hosts
	a, err := New(nil, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "unknown.host").Action)
}

func TestAllowlist_EmptyAllowlistDeniesAll(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "anything.com").Action)
}

func TestAllowlist_MultipleDomains(t *testing.T) {
	a, err := New([]string{"a.com", "b.com", "*.c.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "sub.c.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "d.com").Action)
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	_, err := New(nil, []string{"not-a-cidr"}, &mockResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing CIDR")
}

func TestAllowlist_ResponseIsNoop(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := a.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestAllowlist_Name(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)
	require.Equal(t, "allowlist", a.Name())
}
