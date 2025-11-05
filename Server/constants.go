// Package main defines constants used throughout the Unkn0wnC2 server.
// This centralizes magic numbers and configuration values for maintainability.
package main

import "time"

// DNS and Protocol Constants
const (
	// DNSChunkSize is the maximum chunk size for DNS transmission (tested maximum)
	DNSChunkSize = 403

	// DNSLabelMaxLength is the maximum length for a single DNS label
	DNSLabelMaxLength = 62

	// DNSMaxDomainLength is the maximum total DNS domain name length
	DNSMaxDomainLength = 253
)

// Session and Timeout Constants
const (
	// StagerSessionTimeout is how long stager sessions remain active without activity
	StagerSessionTimeout = 3 * time.Hour

	// ExpectedResultTimeout is how long we wait for chunked results before cleanup
	// This timeout is reset with each chunk received, so long-running multi-hour
	// exfiltrations will not be cleaned up as long as chunks keep arriving.
	// Only cleaned up if NO chunks received for this duration.
	ExpectedResultTimeout = 1 * time.Hour

	// CleanupInterval is how often the cleanup goroutine runs
	CleanupInterval = 5 * time.Minute

	// RecentMessageTTL is how long we track message hashes for deduplication
	RecentMessageTTL = 30 * time.Second

	// TaskTimeout is how long before a sent task is considered failed
	TaskTimeout = 2 * time.Hour
)

// Task and Result Constants
const (
	// TaskCounterStart is the starting ID for task numbering
	TaskCounterStart = 1000

	// ResultPreviewMaxLength is the maximum length of result previews in logs
	ResultPreviewMaxLength = 200

	// MaxCommandLength is the default maximum command length
	MaxCommandLength = 400
)

// Pattern Analysis Constants
const (
	// LegitimateSubdomainMaxLength is the max length for legitimate-looking subdomains
	LegitimateSubdomainMaxLength = 20

	// Base36MinLength is the minimum length for Base36-encoded data
	Base36MinLength = 30

	// Base36LongStringThreshold is the threshold for "definitely encoded" detection
	Base36LongStringThreshold = 50

	// UnixTimestampMinLength is the minimum length of Unix timestamps
	UnixTimestampMinLength = 10

	// UnixTimestampMaxLength is the maximum length of Unix timestamps
	UnixTimestampMaxLength = 11
)

// Console Display Constants
const (
	// BeaconListSeparatorLength is the width of beacon list separators
	BeaconListSeparatorLength = 95

	// TaskListSeparatorLength is the width of task list separators
	TaskListSeparatorLength = 85

	// ResultSeparatorLength is the width of result separators
	ResultSeparatorLength = 50

	// BeaconHostnameWidth is the display width for hostnames
	BeaconHostnameWidth = 20

	// BeaconUsernameWidth is the display width for usernames
	BeaconUsernameWidth = 15

	// TaskCommandWidth is the display width for commands
	TaskCommandWidth = 40
)

// Time Format Constants
const (
	// TimeFormatShort is the short time format for display
	TimeFormatShort = "15:04:05"

	// TimeFormatLong is the long time format for display
	TimeFormatLong = "2006-01-02 15:04:05"
)

// ANSI Color Constants
const (
	// ANSIClearScreen clears the terminal screen
	ANSIClearScreen = "\033[2J\033[H"

	// ColorReset resets terminal color
	ColorReset = "\033[0m"

	// ColorRed sets terminal color to red
	ColorRed = "\033[0;31m"

	// ColorGreen sets terminal color to green
	ColorGreen = "\033[0;32m"

	// ColorYellow sets terminal color to yellow
	ColorYellow = "\033[0;33m"
)

// Progress Bar Constants
const (
	// ProgressBarWidth is the width of progress bars in characters
	ProgressBarWidth = 40

	// ProgressUpdateInterval is how often progress bars update
	ProgressUpdateInterval = 1 * time.Second
)
