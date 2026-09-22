package main

import (
	"sync"
	"testing"
)

// newTestBeacon builds a beacon with only the state the task claim needs, so the mesh
// guarantee can be tested without a network or a running loop.
func newTestBeacon(maxSize int) *Beacon {
	return &Beacon{
		id:              "test-beacon",
		executedTasks:   make(map[string]bool),
		executedMaxSize: maxSize,
	}
}

// TestClaimTask_SecondDeliveryIsSkipped is the client half of the Shadow Mesh guarantee:
// when two mesh nodes hand the same task to one beacon — over DNS and over HTTP, for
// instance — the command runs once.
func TestClaimTask_SecondDeliveryIsSkipped(t *testing.T) {
	beacon := newTestBeacon(100)

	if !beacon.claimTask("T1") {
		t.Fatal("the first delivery did not claim the task")
	}
	if beacon.claimTask("T1") {
		t.Fatal("a second delivery of the same task was claimed again, so the command would run twice")
	}
}

// TestClaimTask_DistinctTasksBothRun asserts dedup is per task, not a blanket refusal.
func TestClaimTask_DistinctTasksBothRun(t *testing.T) {
	beacon := newTestBeacon(100)

	if !beacon.claimTask("T1") {
		t.Fatal("T1 was not claimed")
	}
	if !beacon.claimTask("T2") {
		t.Fatal("T2 was refused; dedup is not per task")
	}
}

// TestClaimTask_ConcurrentDeliveriesExecuteOnce asserts the claim holds under the race it
// exists for. Two mesh nodes delivering simultaneously would both pass a check-then-mark
// implementation, which is why the mark happens before execution.
func TestClaimTask_ConcurrentDeliveriesExecuteOnce(t *testing.T) {
	beacon := newTestBeacon(100)

	const deliveries = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		claimed int
	)

	wg.Add(deliveries)
	for i := 0; i < deliveries; i++ {
		go func() {
			defer wg.Done()
			if beacon.claimTask("T1") {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if claimed != 1 {
		t.Fatalf("%d of %d concurrent deliveries were claimed, want exactly 1", claimed, deliveries)
	}
}

// TestClaimTask_EmptyIDIsNeverClaimed asserts a task with no id is refused rather than run
// untracked, since it cannot be deduplicated or reported against.
func TestClaimTask_EmptyIDIsNeverClaimed(t *testing.T) {
	beacon := newTestBeacon(10)

	if beacon.claimTask("") {
		t.Fatal("a task with no id was claimed")
	}
	if beacon.claimTask("") {
		t.Fatal("a task with no id was claimed twice")
	}
}

// TestClaimTask_HistoryIsBounded asserts the executed-task map cannot grow without limit,
// and that forgetting is oldest-first.
func TestClaimTask_HistoryIsBounded(t *testing.T) {
	beacon := newTestBeacon(3)

	for _, id := range []string{"T1", "T2", "T3", "T4"} {
		if !beacon.claimTask(id) {
			t.Fatalf("failed to claim %s", id)
		}
	}

	if len(beacon.executedTasks) != 3 {
		t.Fatalf("history holds %d entries, want it bounded at 3", len(beacon.executedTasks))
	}
	if len(beacon.executedOrder) != 3 {
		t.Fatalf("order slice holds %d entries, want 3", len(beacon.executedOrder))
	}

	// The oldest claim has been forgotten, so a very late re-delivery of it would run.
	// That is the documented tradeoff of a bounded window, not a silent failure.
	if beacon.executedTasks["T1"] {
		t.Error("the oldest claim was not forgotten first")
	}
	if !beacon.executedTasks["T4"] {
		t.Error("the most recent claim was forgotten")
	}
}
