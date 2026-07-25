// Package server provides a simple colored logger for Hush.
package server

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

const (
	reset  = "\033[0m"
	dim    = "\033[90m"
	blue   = "\033[34m"
	yellow = "\033[33m"
	red    = "\033[31m"
)

// NewLogger creates a colored terminal logger writing to stderr.
// Tag is shown dim before the level, e.g. "21:30:01 [weather] [INF] message"
func NewLogger(tag string) *log.Logger {
	return log.New(&colorWriter{w: os.Stderr, tag: tag}, "", 0)
}

type colorWriter struct {
	w   io.Writer
	tag string
}

func (cw *colorWriter) Write(p []byte) (int, error) {
	ts := time.Now().Format("15:04:05")
	level, msg := parseLevel(p)

	lc := colorForLevel(level)

	var tagPart string
	if cw.tag != "" {
		tagPart = fmt.Sprintf(" [%s%s%s]", dim, cw.tag, reset)
	}

	fmt.Fprintf(cw.w, "%s%s%s%s %s[%s]%s %s",
		dim, ts, reset,
		tagPart,
		lc, level, reset,
		msg,
	)

	return len(p), nil
}

func colorForLevel(level string) string {
	switch level {
	case "INF":
		return blue
	case "WRN":
		return yellow
	case "ERR", "FTL":
		return red
	default:
		return reset
	}
}

func parseLevel(p []byte) (string, string) {
	if len(p) < 6 || p[0] != '[' {
		return "", string(p)
	}
	end := -1
	for i := 1; i < len(p); i++ {
		if p[i] == ']' {
			end = i
			break
		}
	}
	if end < 0 || end+2 >= len(p) {
		return "", string(p)
	}
	return string(p[1:end]), string(p[end+2:])
}
