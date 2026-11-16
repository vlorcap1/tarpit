// Command telarana runs the Telaraña trap-based bot detector.
//
// Usage:
//
//	telarana               start the server (configured by TELARANA_* env vars)
//	telarana healthcheck   exit 0 if the local server answers /healthz
//	telarana version       print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vlorcap1/telarana/internal/config"
	"github.com/vlorcap1/telarana/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const maxRobotsBase = 512 << 10

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("telarana", version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		case "help", "--help", "-h":
			fmt.Print(usage)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "telarana:", err)
		os.Exit(1)
	}
}

const usage = `telarana: trap-based bot detection for reverse proxies

Commands:
  (none)        start the server
  healthcheck   check that the local server is up (for container health checks)
  version       print the version

Configuration is read from TELARANA_* environment variables.
See https://github.com/vlorcap1/telarana#configuration
`

func run() error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := newLogger(cfg)

	var robotsBase string
	if cfg.RobotsFile != "" {
		f, err := os.Open(cfg.RobotsFile)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(f, maxRobotsBase+1))
		f.Close()
		if err != nil {
			return err
		}
		if len(b) > maxRobotsBase {
			return fmt.Errorf("TELARANA_ROBOTS_FILE is larger than %d bytes", maxRobotsBase)
		}
		robotsBase = string(b)
	}

	srv := server.New(cfg, log, server.Options{RobotsBase: robotsBase})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	servers := []*http.Server{newHTTPServer(cfg.Listen, srv.PublicHandler())}
	if cfg.AdminListen != "" {
		servers = append(servers, newHTTPServer(cfg.AdminListen, srv.AdminHandler()))
	}

	errc := make(chan error, len(servers))
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s, ln)
	}

	names := make([]string, 0, len(cfg.GoodBots))
	for _, b := range cfg.GoodBots {
		names = append(names, b.Name)
	}
	log.Info("telarana started", "version", version, "mode", string(cfg.Mode),
		"listen", cfg.Listen, "admin_listen", cfg.AdminListen, "trap_prefix", cfg.TrapPrefix,
		"robots_file", cfg.RobotsFile != "", "trusted_proxies", len(cfg.TrustedProxies),
		"good_bots", strings.Join(names, ","), "secret_rotation", len(cfg.PreviousSecret) > 0)

	go janitor(ctx, srv, cfg.VisitorTTL)

	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Error("server failed", "err", err)
		stop()
	}

	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutCtx)
	}
	return nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func janitor(ctx context.Context, srv *server.Server, ttl time.Duration) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			srv.Store().Sweep(now, ttl)
		}
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// healthcheck queries /healthz on the local listener. It does not need the
// rest of the configuration (in particular, not the secret).
func healthcheck() int {
	addr := os.Getenv("TELARANA_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
