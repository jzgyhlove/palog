// Command server is the palog daemon: multi-device Panabit PNB log receiver
// + SQLite storage + multi-user web console, all in one binary.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"palog/internal/api"
	"palog/internal/receiver"
	"palog/internal/store"
)

func main() {
	dbPath := flag.String("db", "./palog.db", "sqlite database path")
	httpAddr := flag.String("http", "", "HTTP listen address (overrides kv config)")
	adminPw := flag.String("admin-pw", "", "initial admin password (only used when no users exist yet); auto-generated if empty")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	st, err := store.Open(*dbPath)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	cfg, err := st.GetConfig(*dbPath)
	if err != nil {
		slog.Error("read config", "err", err)
		os.Exit(1)
	}
	if *httpAddr != "" {
		cfg.HTTPAddr = *httpAddr
	}

	// Bootstrap the first admin account when the user table is empty.
	n, err := st.CountUsers()
	if err != nil {
		slog.Error("count users", "err", err)
		os.Exit(1)
	}
	if n == 0 {
		pw := *adminPw
		if pw == "" {
			pw = genPassword(16)
			slog.Warn("generated initial admin password", "username", "admin",
				"password", pw, "note", "this is printed ONCE — change it after first login")
		} else {
			slog.Warn("creating initial admin from -admin-pw", "username", "admin")
		}
		admin, err := st.CreateUser(store.User{Username: "admin", Role: store.RoleAdmin, Devices: "*"}, pw)
		if err != nil {
			slog.Error("bootstrap admin", "err", err)
			os.Exit(1)
		}
		slog.Info("admin account ready", "username", admin.Username)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rx := receiver.New(st, 4096)
	go func() {
		if err := rx.Run(ctx); err != nil {
			slog.Error("receiver exited", "err", err)
			stop()
		}
	}()

	started := time.Now()
	srv := &api.Server{Store: st, RX: rx, Started: started, DBPath: *dbPath}
	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("http listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
			stop()
		}
	}()

	// daily retention + session sweep
	retentionDays := cfg.RetentionDays
	if retentionDays > 0 {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				if n, err := st.ApplyRetention(retentionDays); err != nil {
					slog.Error("retention", "err", err)
				} else if n > 0 {
					slog.Info("retention applied", "deleted", n)
				}
				if err := st.CleanExpiredSessions(); err != nil {
					slog.Error("session sweep", "err", err)
				}
			}
		}()
	}

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	select {
	case <-rx.Done():
	case <-shutdownCtx.Done():
		slog.Warn("receiver drain timeout")
	}
	slog.Info("bye")
}

const pwAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func genPassword(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(pwAlphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "change-me-now"
		}
		b[i] = pwAlphabet[idx.Int64()]
	}
	return string(b)
}