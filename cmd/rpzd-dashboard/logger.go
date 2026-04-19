package main

import (
	"log/slog"
	"os"

	"github.com/bodsink/rpzd/config"
)

func newLogger(cfg config.LogConfig) (*slog.Logger, *slog.LevelVar) {
	levelVar := &slog.LevelVar{}
	levelVar.Set(parseLevelVar(cfg.Level))

	opts := &slog.HandlerOptions{Level: levelVar}
	handler := slog.Handler(slog.NewTextHandler(os.Stdout, opts))

	return slog.New(handler), levelVar
}

func parseLevelVar(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
