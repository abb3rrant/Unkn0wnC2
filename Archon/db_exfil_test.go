package main

import (
	"os"
	"testing"
)

func TestStoreExfilChunk_ShadowMesh(t *testing.T) {
	// Setup temporary DB
	dbPath := "test_exfil.db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	db, err := NewMasterDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create DB: %v", err)
	}
	defer db.Close()

	sessionID := "session1"
	totalChunks := 100

	// Simulate Server A sending chunks 1-50
	for i := 1; i <= 50; i++ {
		req := &ExfilChunkStoreRequest{
			SessionID:   sessionID,
			JobID:       "job1",
			DNSServerID: "serverA",
			ChunkIndex:  i,
			TotalChunks: totalChunks,
			FileName:    "test.bin",
			FileSize:    1000,
			Payload:     []byte("A"),
		}
		_, _, err := db.StoreExfilChunk(req)
		if err != nil {
			t.Fatalf("Failed to store chunk %d from Server A: %v", i, err)
		}
	}

	// Check progress
	transfer, err := db.GetExfilTransfer(sessionID)
	if err != nil {
		t.Fatalf("Failed to get transfer: %v", err)
	}
	if transfer.ReceivedChunks != 50 {
		t.Errorf("Expected 50 chunks, got %d", transfer.ReceivedChunks)
	}

	// Simulate Server B sending chunks 51-100
	for i := 51; i <= 100; i++ {
		req := &ExfilChunkStoreRequest{
			SessionID:   sessionID,
			JobID:       "job1",
			DNSServerID: "serverB",
			ChunkIndex:  i,
			TotalChunks: totalChunks,
			FileName:    "test.bin",
			FileSize:    1000,
			Payload:     []byte("B"),
		}
		_, _, err := db.StoreExfilChunk(req)
		if err != nil {
			t.Fatalf("Failed to store chunk %d from Server B: %v", i, err)
		}
	}

	// Check progress
	transfer, err = db.GetExfilTransfer(sessionID)
	if err != nil {
		t.Fatalf("Failed to get transfer: %v", err)
	}
	if transfer.ReceivedChunks != 100 {
		t.Errorf("Expected 100 chunks, got %d", transfer.ReceivedChunks)
	}

	// Test Duplicates: Server B sends chunk 1 (already sent by A)
	req := &ExfilChunkStoreRequest{
		SessionID:   sessionID,
		JobID:       "job1",
		DNSServerID: "serverB",
		ChunkIndex:  1,
		TotalChunks: totalChunks,
		FileName:    "test.bin",
		FileSize:    1000,
		Payload:     []byte("B"), // Different payload, but same index
	}
	_, _, err = db.StoreExfilChunk(req)
	if err != nil {
		t.Fatalf("Failed to store duplicate chunk 1 from Server B: %v", err)
	}

	// Check progress - should still be 100
	transfer, err = db.GetExfilTransfer(sessionID)
	if err != nil {
		t.Fatalf("Failed to get transfer: %v", err)
	}
	if transfer.ReceivedChunks != 100 {
		t.Errorf("Expected 100 chunks after duplicate, got %d", transfer.ReceivedChunks)
	}
}
