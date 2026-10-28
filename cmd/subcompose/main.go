package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ttd/subscription-composer/internal/config"
	"github.com/ttd/subscription-composer/internal/refresh"
	"github.com/ttd/subscription-composer/internal/server"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.json", "Service configuration path")
	check := flag.Bool("check", false, "Fetch, compile and publish once, then print status and exit")
	login := flag.String("ikuuu-login", "", "Authorize an ikuuu source through a native web sign-in window")
	importAuth := flag.String("ikuuu-import", "", "Import and verify authorization for an ikuuu source")
	authFile := flag.String("auth-file", "", "Private callback/session file, or - for standard input")
	authStatus := flag.String("ikuuu-status", "", "Print non-secret stored authorization status for a source")
	loginURL := flag.String("ikuuu-login-url", "https://ikuuu.top/auth/login?redirect=%2Fapi%2Fv2%2Fweb-auth%2Fcall-client", "Official website sign-in URL")
	helper := flag.String("login-helper", "", "Path to the native ikuuu-login helper")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	authActions := 0
	for _, value := range []string{*login, *importAuth, *authStatus} {
		if value != "" {
			authActions++
		}
	}
	if authActions > 1 || (authActions > 0 && *check) || (*authFile != "" && *importAuth == "") {
		return fmt.Errorf("choose one authorization action; auth-file requires ikuuu-import")
	}
	if authActions > 0 {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAuth(ctx, cfg, authOptions{Login: *login, Import: *importAuth, Status: *authStatus, File: *authFile, LoginURL: *loginURL, Helper: *helper})
	}
	manager, err := refresh.New(cfg)
	if err != nil {
		return fmt.Errorf("initialize snapshots: %w", err)
	}
	if *check {
		err = manager.Refresh(context.Background(), true)
		_ = json.NewEncoder(os.Stdout).Encode(manager.Status())
		if err != nil {
			return fmt.Errorf("refresh failed; see status")
		}
		return nil
	}
	timeout, _ := time.ParseDuration(cfg.RefreshTimeout)
	srv := &http.Server{Addr: cfg.Listen, Handler: server.New(manager, cfg.Devices), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: timeout + 10*time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	log.Printf("subscription service listening on %s", cfg.Listen)
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
	return nil
}
