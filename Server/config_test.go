package main

import (
	"strings"
	"testing"
)

func TestConfigValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() should validate clean, got error: %v", err)
	}
}

func TestConfigValidate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterServer = "https://master.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fully valid config should return nil, got error: %v", err)
	}
}

func TestConfigValidate_BindPortOutOfRange(t *testing.T) {
	for _, port := range []int{0, 65536} {
		cfg := DefaultConfig()
		cfg.BindPort = port
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("BindPort %d should be invalid, got nil error", port)
		}
		if !strings.Contains(err.Error(), "BindPort") {
			t.Errorf("BindPort %d error should mention BindPort, got: %v", port, err)
		}
	}
}

func TestConfigValidate_EmptyDomain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty Domain should be invalid, got nil error")
	}
	if !strings.Contains(err.Error(), "Domain") {
		t.Errorf("empty Domain error should mention Domain, got: %v", err)
	}
}

func TestConfigValidate_EmptyNS1(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NS1 = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty NS1 should be invalid, got nil error")
	}
	if !strings.Contains(err.Error(), "NS1") {
		t.Errorf("empty NS1 error should mention NS1, got: %v", err)
	}
}

func TestConfigValidate_EmptyNS2(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NS2 = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty NS2 should be invalid, got nil error")
	}
	if !strings.Contains(err.Error(), "NS2") {
		t.Errorf("empty NS2 error should mention NS2, got: %v", err)
	}
}

func TestConfigValidate_EmptyEncryptionKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EncryptionKey = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty EncryptionKey should be invalid, got nil error")
	}
	if !strings.Contains(err.Error(), "EncryptionKey") {
		t.Errorf("empty EncryptionKey error should mention EncryptionKey, got: %v", err)
	}
}

func TestConfigValidate_EmptyMasterServer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterServer = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty MasterServer should be invalid, got nil error")
	}
	if !strings.Contains(err.Error(), "MasterServer") {
		t.Errorf("empty MasterServer error should mention MasterServer, got: %v", err)
	}
}
