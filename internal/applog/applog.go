// Package applog is the HashHarvest logger: a rotating file under
// ~/.hashharvest/logs/, the console, and per-scan capture so a scan's log
// can be stored with its record.
package applog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxBytes    = 1_000_000
	backupCount = 5
)

var (
	mu       sync.Mutex
	logPath  string // "" until Setup succeeds in creating the log directory
	console  bool
	captures []*bytes.Buffer
)

// Setup enables file and console logging. It is safe to call more than
// once. A read-only home directory leaves console-only logging.
//
// The Python app also read HASHHARVEST_LOG_LEVEL, but its only log calls
// happen during a scan, where capture forces INFO, so the variable never
// changed the output; it is not consulted here.
func Setup() {
	mu.Lock()
	defer mu.Unlock()
	console = true
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".hashharvest", "logs")
	if os.MkdirAll(dir, 0o755) == nil {
		logPath = filepath.Join(dir, "hashharvest.log")
	}
}

// Info logs a message under the given logger name.
func Info(name, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	now := time.Now()
	// Python's %(asctime)s: local time with comma-separated milliseconds.
	full := fmt.Sprintf("%s,%03d INFO %s: %s\n", now.Format("2006-01-02 15:04:05"), now.Nanosecond()/1e6, name, msg)

	mu.Lock()
	defer mu.Unlock()
	for _, buf := range captures {
		buf.WriteString(full)
	}
	if console {
		fmt.Fprintf(os.Stderr, "INFO %s: %s\n", name, msg)
	}
	if logPath != "" {
		appendRotating(logPath, full)
	}
}

// Capture starts buffering every message logged until stop is called, and
// returns the buffered text from stop.
func Capture() (stop func() string) {
	buf := &bytes.Buffer{}
	mu.Lock()
	captures = append(captures, buf)
	mu.Unlock()
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		for i, b := range captures {
			if b == buf {
				captures = append(captures[:i], captures[i+1:]...)
				break
			}
		}
		return buf.String()
	}
}

// appendRotating appends to path, first rolling path -> path.1 -> ... ->
// path.5 when the write would reach maxBytes. Logging failures are dropped:
// they must never break a scan.
func appendRotating(path, text string) {
	if info, err := os.Stat(path); err == nil && info.Size() > 0 && info.Size()+int64(len(text)) >= maxBytes {
		for i := backupCount - 1; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
		}
		os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(text)
}
