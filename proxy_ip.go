package proxy_ip

import (
	"context"
	"net"
	"net/http"

	goproxy "github.com/pires/go-proxyproto"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(ProxyIp{})
	httpcaddyfile.RegisterHandlerDirective("proxy_ip", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("proxy_ip", httpcaddyfile.Before, "rewrite")
	caddy.RegisterModule(MatchProxyIp{})
}

type ctxKey struct{}

type ProxyIp struct{}

func (ProxyIp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.proxy_ip",
		New: func() caddy.Module { return new(ProxyIp) },
	}
}

func (p *ProxyIp) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App("http")
	if err != nil {
		return err
	}
	app := appModule.(*caddyhttp.App)

	for _, srv := range app.Servers {
		srv.RegisterConnContext(func(ctx context.Context, c net.Conn) context.Context {
			proxyIp := extractProxyIp(c)
			return context.WithValue(ctx, ctxKey{}, proxyIp)
		})
	}

	return nil
}

func extractProxyIp(c net.Conn) string {
	const maxDepth = 10
	for range maxDepth {
		if pc, ok := c.(*goproxy.Conn); ok {
			if raw := pc.Raw(); raw != nil {
				host, _, err := net.SplitHostPort(raw.RemoteAddr().String())
				if err == nil {
					return host
				}
				return raw.RemoteAddr().String()
			}
			return ""
		}

		if unwrapper, ok := c.(interface{ Unwrap() net.Conn }); ok {
			c = unwrapper.Unwrap()
			continue
		}
		if unwrapper, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = unwrapper.NetConn()
			continue
		}
		if unwrapper, ok := c.(interface{ Conn() net.Conn }); ok {
			c = unwrapper.Conn()
			continue
		}

		break
	}
	return ""
}

func (p ProxyIp) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if proxyIp, ok := r.Context().Value(ctxKey{}).(string); ok && proxyIp != "" {
		caddyhttp.SetVar(r.Context(), "proxy_ip", proxyIp)
	}
	return next.ServeHTTP(w, r)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p ProxyIp
	return &p, nil
}

func (p *ProxyIp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

type MatchProxyIp struct {
	Ranges []string `json:"ranges,omitempty"`

	cidrs []*net.IPNet
}

func (MatchProxyIp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.proxy_ip",
		New: func() caddy.Module { return new(MatchProxyIp) },
	}
}

func (m *MatchProxyIp) Provision(ctx caddy.Context) error {
	for _, r := range m.Ranges {
		if _, cidr, err := net.ParseCIDR(r); err == nil {
			m.cidrs = append(m.cidrs, cidr)
		} else if ip := net.ParseIP(r); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			m.cidrs = append(m.cidrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nil
}

func (m MatchProxyIp) MatchWithError(r *http.Request) (bool, error) {
	proxyIp, ok := r.Context().Value(ctxKey{}).(string)
	if !ok || proxyIp == "" {
		return len(m.Ranges) == 0, nil
	}

	ip := net.ParseIP(proxyIp)
	if ip == nil {
		return false, nil
	}

	for _, cidr := range m.cidrs {
		if cidr.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

func (m *MatchProxyIp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextArg() {
			m.Ranges = append(m.Ranges, d.Val())
		}
		for d.NextBlock(0) {
			m.Ranges = append(m.Ranges, d.Val())
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*ProxyIp)(nil)
	_ caddyhttp.MiddlewareHandler = (*ProxyIp)(nil)
	_ caddyfile.Unmarshaler       = (*ProxyIp)(nil)

	_ caddy.Provisioner                 = (*MatchProxyIp)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchProxyIp)(nil)
	_ caddyfile.Unmarshaler             = (*MatchProxyIp)(nil)
)
