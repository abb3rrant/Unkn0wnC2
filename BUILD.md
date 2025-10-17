# Unkn0wnC2 Build System

This document describes the unified build system for the Unkn0wnC2 DNS C2 framework.

## Overview

The build system consolidates configuration management and creates production-ready binaries for all supported platforms. It embeds configuration at build time for security and simplicity.

## Build Configuration

All build settings are managed through the master `build_config.json` file at the project root:

```json
{
  "project": {
    "name": "Unkn0wnC2",
    "version": "1.0.0",
    "description": "DNS-based Command & Control Framework"
  },
  "server": {
    "bind_addr": "172.26.13.62",
    "bind_port": 53,
    "server_address": "98.90.218.70",
    "domain": "secwolf.net",
    "ns1": "ns1.secwolf.net",
    "ns2": "ns2.secwolf.net",
    "forward_dns": true,
    "upstream_dns": "8.8.8.8:53",
    "debug": false
  },
  "client": {
    "server_domain": "secwolf.net",
    "dns_server": "",
    "query_type": "TXT",
    "encoding": "aes-gcm-base36",
    "timeout": 10,
    "max_command_length": 800,
    "retry_attempts": 3,
    "sleep_min": 5,
    "sleep_max": 15
  },
  "security": {
    "encryption_key": "MySecretC2Key123!@#DefaultChange"
  },
  "build": {
    "output_dir": "build",
    "targets": {
      "server": {
        "linux": {
          "enabled": true,
          "output": "dns-server-linux"
        }
      },
      "client": {
        "windows": {
          "enabled": true,
          "output": "dns-client-windows.exe"
        },
        "linux": {
          "enabled": true,
          "output": "dns-client-linux"
        }
      }
    }
  }
}
```

## Building

### Quick Start

**Windows:**
```cmd
build.bat
```

**Linux/macOS:**
```bash
chmod +x build.sh
./build.sh
```

### Manual Build Process

1. **Configure**: Edit `build_config.json` with your settings
2. **Build Tool**: The build script compiles the build tool from `tools/builder/`
3. **Generate Configs**: Creates embedded configuration files for server and client
4. **Compile Binaries**: Cross-compiles for all enabled target platforms
5. **Package**: Creates deployment information and organizes output

### Build Output

All build artifacts are placed in the `build/` directory:

```
build/
├── dns-server-linux          # Linux server binary
├── dns-client-windows.exe    # Windows client binary  
├── dns-client-linux          # Linux client binary
└── deployment_info.json      # Build and deployment information
```

## Configuration Embedding

### Server Configuration

The server uses a layered configuration approach:

1. **Embedded Config**: Configuration baked into the binary at build time
2. **Runtime Config**: Optional `config.json` file for deployment-specific overrides
3. **Environment**: `DNS_CONFIG` environment variable to specify alternate config file

### Client Configuration

Clients use fully embedded configuration with no external dependencies. All settings are compiled into the binary for operational security.

## Security Notes

### Important: Change Default Encryption Key

The default encryption key `"MySecretC2Key123!@#DefaultChange"` **MUST** be changed before deployment:

```json
{
  "security": {
    "encryption_key": "YourSecureRandomKey256BitsLong!"
  }
}
```

### Build-time Security

- Configuration is embedded at build time
- No external config files needed for clients
- Encryption keys are compiled into binaries
- Source configuration files should be secured

## Deployment

### Server Deployment

1. Transfer `dns-server-linux` to your server
2. Configure DNS delegation for your domain
3. Set up proper firewall rules (UDP port 53)
4. Run with appropriate privileges: `sudo ./dns-server-linux`

### Client Deployment

1. Clients are completely standalone - no additional files needed
2. Transfer appropriate binary (`dns-client-windows.exe` or `dns-client-linux`)
3. Execute directly - configuration is embedded

### Domain Setup

Ensure proper DNS delegation:

1. Register your domain with registrar
2. Set NS records to point to your server
3. Configure glue records with registrar
4. Test DNS resolution: `nslookup ns1.yourdomain.com`

## Build Targets

Currently supported build targets:

- **Server**: Linux/AMD64 only (typical server deployment)
- **Client**: Windows/AMD64 and Linux/AMD64

Additional targets can be added by modifying the `build_config.json` targets section and updating the build tool.

## Troubleshooting

### Build Failures

- Ensure Go 1.21+ is installed and in PATH
- Verify `build_config.json` syntax with JSON validator  
- Check that all required directories exist
- Run `go mod tidy` in Server/ and Client/ directories if needed

### Configuration Issues

- Validate JSON syntax in `build_config.json`
- Ensure encryption keys match between server and client sections
- Verify domain names are properly formatted
- Check that bind addresses are valid for your server

### Runtime Issues

- Test DNS resolution with `dig` or `nslookup`
- Verify firewall allows UDP/53 traffic
- Check server logs with debug mode enabled
- Ensure proper DNS delegation is configured

## Development

### Adding New Build Targets

1. Edit `build_config.json` to add new target platform
2. Update `tools/builder/main.go` to handle the new target
3. Test cross-compilation: `GOOS=target GOARCH=arch go build`

### Modifying Configuration

1. Update the relevant struct in `tools/builder/main.go`
2. Modify configuration generation functions
3. Update this documentation

### Testing Builds

Always test builds on target platforms before deployment:

```bash
# Test server
./build/dns-server-linux -d  # Enable debug mode

# Test clients  
./build/dns-client-linux
./build/dns-client-windows.exe  # (on Windows or via Wine)
```