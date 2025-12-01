// Package main provides logging functionality for the Archon Master Server.
// Logs are always written to file, and optionally to stdout when debug mode is enabled.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger handles logging to both file and optionally stdout
type Logger struct {
	file       *os.File
	logger     *log.Logger
	debugMode  bool
	mu         sync.Mutex
	logDir     string
	currentDay string
}

var (
	appLogger *Logger
	logOnce   sync.Once
)

// InitLogger initializes the global logger
// logDir: directory to store log files (e.g., /opt/unkn0wnc2/logs/)
// debugMode: if true, also output to stdout
func InitLogger(logDir string, debugMode bool) error {
	var initErr error
	logOnce.Do(func() {
		// Create log directory if it doesn't exist
		if err := os.MkdirAll(logDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create log directory: %w", err)
			return
		}

		appLogger = &Logger{
			debugMode: debugMode,
			logDir:    logDir,
		}

		if err := appLogger.rotateLogFile(); err != nil {
			initErr = fmt.Errorf("failed to open log file: %w", err)
			return
		}

		// Start log rotation checker
		go appLogger.rotationChecker()
	})
	return initErr
}

// rotateLogFile opens a new log file for the current day
func (l *Logger) rotateLogFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if l.currentDay == today && l.file != nil {
		return nil
	}

	// Close existing file if open
	if l.file != nil {
		l.file.Close()
	}

	// Open new log file
	logPath := filepath.Join(l.logDir, fmt.Sprintf("archon-%s.log", today))
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	l.file = file
	l.currentDay = today

	// Create logger with appropriate output
	var output io.Writer
	if l.debugMode {
		output = io.MultiWriter(file, os.Stdout)
	} else {
		output = file
	}
	l.logger = log.New(output, "", 0)

	return nil
}

// rotationChecker checks daily if log file needs rotation
func (l *Logger) rotationChecker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		l.rotateLogFile()
	}
}

// Log writes a log message with timestamp
func (l *Logger) Log(level, format string, args ...interface{}) {
	if l == nil || l.logger == nil {
		// Fallback to stdout if logger not initialized
		fmt.Printf("[%s] %s\n", level, fmt.Sprintf(format, args...))
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s] %s", timestamp, level, msg)
}

// Close closes the log file
func (l *Logger) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
	}
}

// Package-level logging functions

// LogInfo logs an informational message
func LogInfo(format string, args ...interface{}) {
	if appLogger != nil {
		appLogger.Log("INFO", format, args...)
	} else {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

// LogDebug logs a debug message
func LogDebug(format string, args ...interface{}) {
	if appLogger != nil {
		appLogger.Log("DEBUG", format, args...)
	} else {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// LogWarn logs a warning message
func LogWarn(format string, args ...interface{}) {
	if appLogger != nil {
		appLogger.Log("WARN", format, args...)
	} else {
		fmt.Printf("[WARN] "+format+"\n", args...)
	}
}

// LogError logs an error message
func LogError(format string, args ...interface{}) {
	if appLogger != nil {
		appLogger.Log("ERROR", format, args...)
	} else {
		fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
	}
}

// CloseLogger closes the global logger
func CloseLogger() {
	if appLogger != nil {
		appLogger.Close()
	}
}
