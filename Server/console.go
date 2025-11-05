// Package main provides logging utilities for the DNS C2 server.
// This file contains the logf() function used throughout the codebase for
// thread-safe formatted logging.
package main

import "log"

// logf provides thread-safe formatted logging for the DNS C2 server.
// All log output from the DNS server components should use this function
// to ensure consistent formatting and thread safety.
func logf(format string, v ...interface{}) {
	log.Printf(format, v...)
}
