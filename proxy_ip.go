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
			proxyIP := extractProxyIP(c)
			return context.WithValue(ctx, ctxKey{}, proxyIP)
		})
	}

	return nil
}

func extractProxyIP(c net.Conn) string {
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
	if proxyIP, ok := r.Context().Value(ctxKey{}).(string); ok && proxyIP != "" {
		caddyhttp.SetVar(r.Context(), "proxy_ip", proxyIP)
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

var (
	_ caddy.Provisioner           = (*ProxyIp)(nil)
	_ caddyhttp.MiddlewareHandler = (*ProxyIp)(nil)
	_ caddyfile.Unmarshaler       = (*ProxyIp)(nil)
)
