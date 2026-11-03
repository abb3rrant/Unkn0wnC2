package main

import (
	"fmt"
	"time"
)

// Abandoned-task sweep.
//
// A task queued to a beacon that then dies stays "pending" forever: nothing polls
// for it, and nothing ever will. The liveness guard stops new work being queued to
// a silent beacon, but it cannot help work that was queued while the beacon was
// still alive — and that is the ordinary case, not an edge case: a beacon can die
// one second after accepting a task.
//
// The sweep closes the ledger. Every queued task whose beacon has been silent for
// longer than the grace period is marked failed, with a result row that says why,
// so the UI shows an outcome instead of an indefinite "pending".

const (
	// orphanedTaskBeaconSilence is how long a beacon must be silent before its
	// outstanding tasks are abandoned. It is deliberately much longer than one poll
	// window: this is a cleanup, and a false positive cancels work that might still
	// have been delivered.
	orphanedTaskBeaconSilence = 30 * time.Minute
	// orphanedTaskSweepInterval is how often the sweep runs.
	orphanedTaskSweepInterval = 5 * time.Minute
)

// FailTasksForDeadBeacons marks outstanding tasks as failed when their beacon has
// been silent past the grace period, and records the reason as a result row.
func (d *MasterDatabase) FailTasksForDeadBeacons() (int64, error) {
	now := time.Now().Unix()
	threshold := now - int64(orphanedTaskBeaconSilence.Seconds())

	rows, err := d.db.Query(`
		SELECT t.id, t.beacon_id, COALESCE(t.assigned_dns_server, ''), b.last_seen
		FROM tasks t
		JOIN beacons b ON b.id = t.beacon_id
		WHERE t.status IN ('pending', 'sent') AND b.last_seen < ?
	`, threshold)
	if err != nil {
		return 0, err
	}

	type abandoned struct {
		taskID, beaconID, serverID string
		lastSeen                   int64
	}
	var pending []abandoned
	for rows.Next() {
		var item abandoned
		if err := rows.Scan(&item.taskID, &item.beaconID, &item.serverID, &item.lastSeen); err != nil {
			_ = rows.Close()
			return 0, err
		}
		pending = append(pending, item)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var failed int64
	for _, item := range pending {
		reason := fmt.Sprintf("beacon has not checked in since %s; task abandoned — the beacon process is gone",
			time.Unix(item.lastSeen, 0).UTC().Format(time.RFC3339))

		tx, err := d.db.Begin()
		if err != nil {
			return failed, err
		}
		if _, err := tx.Exec(`
			UPDATE tasks SET status = 'failed', completed_at = ?, updated_at = ? WHERE id = ?
		`, now, now, item.taskID); err != nil {
			_ = tx.Rollback()
			return failed, err
		}
		// A reason is only useful if it travels the same way a real result does.
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
			VALUES (?, ?, ?, ?, ?, 0, 1, 1)
		`, item.taskID, item.beaconID, item.serverID, reason, now); err != nil {
			_ = tx.Rollback()
			return failed, err
		}
		if err := tx.Commit(); err != nil {
			return failed, err
		}
		failed++
	}
	return failed, nil
}

// StartAbandonedTaskSweeper runs the sweep at startup and then on an interval.
// A failure is logged and retried on the next tick: a sweep that stops after one
// error would leave the ledger stuck for the life of the process.
func StartAbandonedTaskSweeper(db *MasterDatabase) {
	sweep := func() {
		failed, err := db.FailTasksForDeadBeacons()
		if err != nil {
			LogWarn("task sweep failed: %v", err)
			return
		}
		if failed > 0 {
			LogInfo("task sweep abandoned %d task(s) for beacons that are gone", failed)
		}
	}

	go func() {
		sweep()
		ticker := time.NewTicker(orphanedTaskSweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			sweep()
		}
	}()
}
