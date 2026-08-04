package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/buildkite/github-api-proxy/internal/service"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := service.Run(ctx, os.Getenv); err != nil {
		slog.Error("github-api-proxy stopped", "error", err)
		os.Exit(1)
	}
}
