// Command server is the palog daemon: Panabit PNB log receiver + SQLite
// storage + web console, all in one binary.
package main

import (
	"context"
	"flag"
	"log/slog"
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
	udpAddr := flag.String("udp", "", "UDP listen address (overrides kv config)")
	httpAddr := flag.String("http", "", "HTTP listen address (overrides kv config)")
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
	if *udpAddr != "" {
		cfg.ListenUDP = *udpAddr
	}
	if *httpAddr != "" {
		cfg.HTTPAddr = *httpAddr
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rx := receiver.New(st, cfg.ListenUDP, 4096)
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

	// daily retention
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