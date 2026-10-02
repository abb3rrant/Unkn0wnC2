//go:build !generated

package main

// This inert configuration exists so a clean checkout can be compiled, vetted,
// and tested. Archon writes config.go and builds with the generated tag for every
// deployable beacon; this file is excluded from those builds.
var embeddedConfig = Config{
	ServerDomain:        "example.invalid",
	DNSDomains:          []string{"example.invalid"},
	DomainSelectionMode: "random",
	QueryType:           "TXT",
	Encoding:            "aes-gcm-base36",
	EncryptionKey:       "local-development-test-key-not-a-real-key",
	Timeout:             10,
	MaxCommandLength:    400,
	RetryAttempts:       3,
	SleepMin:            1,
	SleepMax:            2,
	ExfilJitterMinMs:    100,
	ExfilJitterMaxMs:    200,
	ExfilChunksPerBurst: 10,
	ExfilBurstPauseMs:   1000,
	BeaconName:          "development-only",
	BuildID:             "devstub",
	Registration: PhaseConfig{
		QueryType:    "TXT",
		Encrypted:    true,
		ARecordACKIP: "127.0.0.1",
	},
	Poll: PollPhaseConfig{
		PhaseConfig: PhaseConfig{
			QueryType:    "TXT",
			Encrypted:    true,
			ARecordACKIP: "127.0.0.1",
		},
		ARecordTaskIP: "127.0.0.2",
	},
	DataExfil: PhaseConfig{
		QueryType:    "TXT",
		Encrypted:    true,
		ARecordACKIP: "127.0.0.1",
	},
	Transport:                 "dns",
	HTTPFallbackAfterFailures: 3,
	HTTPRetryBackoffSecs:      60,
}

func getConfig() Config {
	return embeddedConfig
}
