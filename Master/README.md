# Unkn0wnC2 Master Server

**Status:** Development (feature-shadow-mesh branch)

The Master Server is the central command and control hub for distributed Unkn0wnC2 deployments. It provides:
- 🌐 HTTPS API for DNS server coordination
- 🖥️ Web-based UI for operators (login & dashboard)
- 📊 Aggregated beacon and task management across multiple DNS servers
- 👥 Multi-user support with role-based access
- 📝 Comprehensive audit logging

---

## Architecture

```
┌──────────────────────────────┐
│     Master Server            │
│  - WebUI (React/Vue)         │
│  - HTTPS API                 │
│  - Master Database (SQLite)  │
│  - Multi-user Support        │
│  - Aggregated Data           │
└───────┬──────────────────────┘
        │ HTTPS (encrypted)
  ┌─────┴─────┬─────────────┐
  │           │             │
DNS Server  DNS Server  DNS Server
(Port 53)   (Port 53)   (Port 53)
```

---

## Setup

### Prerequisites
- Go 1.24+
- TLS certificates (for HTTPS)

### Installation

1. **Install dependencies**
```bash
cd Master
go mod download
```

2. **Generate TLS certificates** (for development)
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/master.key \
  -out certs/master.crt -days 365 -nodes \
  -subj "/CN=master.unkn0wnc2.local"
```

3. **Generate example configuration**
```bash
go run . --generate-config
```

This creates `master_config.json` with default settings.

4. **Edit configuration**
```json
{
  "bind_addr": "0.0.0.0",
  "bind_port": 8443,
  "tls_cert": "certs/master.crt",
  "tls_key": "certs/master.key",
  "database_path": "master.db",
  "jwt_secret": "CHANGE_THIS_SECRET_IN_PRODUCTION",
  "session_timeout": 60,
  "debug": false,
  "dns_servers": [
    {
      "id": "dns1",
      "domain": "secwolf.net",
      "api_key": "your-secure-api-key-here",
      "address": "98.90.218.70",
      "enabled": true
    }
  ],
  "admin_credentials": {
    "username": "admin",
    "password": "CHANGE_THIS_PASSWORD"
  }
}
```

5. **Build and run**
```bash
go build -o master
./master
```

---

## Configuration Reference

### Master Server Settings

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `bind_addr` | string | Address to bind HTTPS server | `"0.0.0.0"` |
| `bind_port` | int | HTTPS port | `8443` |
| `tls_cert` | string | Path to TLS certificate | `"certs/master.crt"` |
| `tls_key` | string | Path to TLS private key | `"certs/master.key"` |
| `database_path` | string | SQLite database file path | `"master.db"` |
| `jwt_secret` | string | Secret for JWT token signing | ⚠️ Must be changed |
| `session_timeout` | int | Session timeout in minutes | `60` |
| `debug` | bool | Enable debug logging | `false` |

### DNS Server Registration

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique DNS server identifier |
| `domain` | string | DNS domain this server handles |
| `api_key` | string | API key for authentication |
| `address` | string | Expected IP address (optional) |
| `enabled` | bool | Whether server is enabled |

### Admin Credentials

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Initial admin username |
| `password` | string | Initial admin password (will be hashed) |

---

## Database Schema

### Tables

1. **dns_servers**: Registered DNS servers
2. **beacons**: Aggregated beacon data from all DNS servers
3. **tasks**: Centralized task management
4. **task_results**: Task results from beacons
5. **operators**: Operator accounts
6. **audit_log**: Audit trail of operator actions
7. **sessions**: JWT session tracking

See `db.go` for complete schema definitions.

---

## Web Interface

The Master server includes a modern web interface for managing the C2 infrastructure.

### Accessing the Web UI

Navigate to:
```
https://<master-ip>:8443/
```

Default login:
- **Username**: `admin`
- **Password**: (from `master_config.json`)

### Features

- **Login Page** (`/login`): Secure JWT authentication
- **Dashboard** (`/dashboard`): Real-time overview
  - Active beacon count and listing
  - DNS server status monitoring
  - Auto-refresh every 10 seconds

### Development

See [web/README.md](web/README.md) for detailed web interface documentation.

---

## API Endpoints

### Authentication
- `POST /api/auth/login` - Operator login (returns JWT token)
- `POST /api/auth/logout` - Operator logout

### Web UI
- `GET /` - Redirect to login
- `GET /login` - Login page
- `GET /dashboard` - Dashboard (requires authentication)

### DNS Server Management
- `GET /api/dns-servers` - List all DNS servers
- `GET /api/dns-servers/:id` - Get DNS server details
- `POST /api/dns-servers` - Register new DNS server
- `DELETE /api/dns-servers/:id` - Remove DNS server

### Beacon Management
- `GET /api/beacons` - List all beacons (aggregated)
- `GET /api/beacons/:id` - Get beacon details
- `POST /api/beacons/:id/task` - Create task for beacon

### Task Management
- `GET /api/tasks` - List all tasks
- `GET /api/tasks/:id` - Get task details
- `GET /api/tasks/:id/result` - Get task result

### DNS Server Communication
- `POST /api/dns-server/checkin` - DNS server check-in
- `POST /api/dns-server/beacon` - Report new beacon
- `POST /api/dns-server/result` - Submit task result
- `GET /api/dns-server/tasks` - Get pending tasks

---

## Security

### Production Checklist

- [ ] Change default `jwt_secret`
- [ ] Change default admin password
- [ ] Use valid TLS certificates (not self-signed)
- [ ] Generate unique API keys for each DNS server
- [ ] Enable audit logging
- [ ] Restrict `bind_addr` to specific interface (not 0.0.0.0)
- [ ] Implement firewall rules (only DNS servers should access API)
- [ ] Regular backup of `master.db`
- [ ] Monitor audit logs for suspicious activity

### API Key Generation

Generate secure API keys for DNS servers:
```bash
openssl rand -base64 32
```

### JWT Secret Generation

Generate a secure JWT secret:
```bash
openssl rand -base64 64
```

---

## Development

### Building
```bash
go build -o master
```

### Running in Debug Mode
```bash
./master --debug
```

or set in config:
```json
{
  "debug": true
}
```

### Database Management

View database stats:
```bash
sqlite3 master.db "SELECT * FROM dns_servers;"
```

---

## Deployment

### Docker (Coming Soon)
- Dockerfile
- docker-compose.yml for full stack deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/unkn0wnc2-master.service`:
```ini
[Unit]
Description=Unkn0wnC2 Master Server
After=network.target

[Service]
Type=simple
User=unkn0wn
WorkingDirectory=/opt/unkn0wnc2/master
ExecStart=/opt/unkn0wnc2/master/master
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable unkn0wnc2-master
sudo systemctl start unkn0wnc2-master
```

---

## Troubleshooting

### TLS Certificate Issues
```
Error: TLS certificate not found: certs/master.crt
```
**Solution**: Generate certificates (see Installation step 2)

### Database Locked
```
Error: database is locked
```
**Solution**: Ensure only one Master server instance is running

### DNS Server Can't Connect
```
DNS Server error: connection refused
```
**Solution**: 
- Check firewall rules
- Verify Master server is running
- Check DNS server has correct master_url in config

---

## Future Enhancements

- [ ] Task creation interface in web UI
- [ ] WebSocket support for real-time updates
- [ ] Advanced task scheduling
- [ ] Beacon grouping and filtering
- [ ] Task history and results viewer in UI
- [ ] Operator management interface
- [ ] Audit log viewer in UI
- [ ] Export/import functionality
- [ ] Metrics and monitoring endpoints
- [ ] Multi-language support

---

## License

See main project README
