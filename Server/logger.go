// Package main provides logging functionality for the DNS Server.
// Logs are always written to file in the same directory as the server,
// and optionally to stdout when debug mode is enabled.
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
	serverLogger *Logger
	logOnce      sync.Once
)

// InitLogger initializes the global logger
// If logDir is empty, uses the current working directory
// debugMode: if true, also output to stdout
func InitLogger(logDir string, debugMode bool) error {
	var initErr error
	logOnce.Do(func() {
		// Use current directory if not specified
		if logDir == "" {
			var err error
			logDir, err = os.Getwd()
			if err != nil {
				logDir = "."
			}
		}

		// Create log directory if it doesn't exist
		if err := os.MkdirAll(logDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create log directory: %w", err)
			return
		}

		serverLogger = &Logger{
			debugMode: debugMode,
			logDir:    logDir,
		}

		if err := serverLogger.rotateLogFile(); err != nil {
			initErr = fmt.Errorf("failed to open log file: %w", err)
			return
		}

		// Start log rotation checker
		go serverLogger.rotationChecker()
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
	logPath := filepath.Join(l.logDir, fmt.Sprintf("dns-server-%s.log", today))
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
		if debugMode {
			fmt.Printf("[%s] %s\n", level, fmt.Sprintf(format, args...))
		}
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
	if serverLogger != nil {
		serverLogger.Log("INFO", format, args...)
	} else if debugMode {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

// LogDebug logs a debug message
func LogDebug(format string, args ...interface{}) {
	if serverLogger != nil {
		serverLogger.Log("DEBUG", format, args...)
	} else if debugMode {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// LogWarn logs a warning message
func LogWarn(format string, args ...interface{}) {
	if serverLogger != nil {
		serverLogger.Log("WARN", format, args...)
	} else if debugMode {
		fmt.Printf("[WARN] "+format+"\n", args...)
	}
}

// LogError logs an error message
func LogError(format string, args ...interface{}) {
	if serverLogger != nil {
		serverLogger.Log("ERROR", format, args...)
	} else {
		// Always print errors to stderr
		fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
	}
}

// CloseLogger closes the global logger
func CloseLogger() {
	if serverLogger != nil {
		serverLogger.Close()
	}
}
