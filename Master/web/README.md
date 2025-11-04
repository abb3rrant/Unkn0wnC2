# Unkn0wnC2 Web Interface

Modern web-based management interface for the Unkn0wnC2 Master Server.

## Features

- **Authentication**: JWT-based login system
- **Dashboard**: Real-time overview of beacons and DNS servers
- **Beacon Management**: View all active beacons across distributed DNS servers
- **DNS Server Monitoring**: Monitor health and status of lieutenant servers
- **Dark Theme**: Modern, responsive design optimized for security operations

## Access

The web interface is automatically served by the Master server:

```
https://<master-ip>:8443/
```

Default admin credentials:
- Username: `admin`
- Password: (set in `master_config.json`)

## Pages

### Login (`/login`)
- Secure JWT authentication
- Auto-redirect if already logged in
- Error handling with visual feedback

### Dashboard (`/dashboard`)
- Active beacon count and listing
- DNS server status and monitoring
- Auto-refresh every 10 seconds
- Responsive tables with real-time data

## API Endpoints Used

### Authentication
- `POST /api/auth/login` - Authenticate and receive JWT token
- `POST /api/auth/logout` - Invalidate session

### Beacons
- `GET /api/beacons` - List all active beacons

### DNS Servers
- `GET /api/dns-servers` - List all registered DNS servers

## Development

### File Structure
```
web/
├── login.html          # Authentication page
├── dashboard.html      # Main dashboard
├── static/            # Static assets (CSS, JS, images)
└── README.md          # This file
```

### Adding New Pages

1. Create HTML file in `web/` directory
2. Add route handler in `Master/api.go`:
   ```go
   router.HandleFunc("/newpage", api.handleNewPage).Methods("GET")
   ```
3. Implement handler:
   ```go
   func (api *APIServer) handleNewPage(w http.ResponseWriter, r *http.Request) {
       http.ServeFile(w, r, "./web/newpage.html")
   }
   ```

### Adding API Endpoints

1. Define request/response structures in `api.go`
2. Implement handler function
3. Add route to `SetupRoutes()`:
   ```go
   operatorRouter.HandleFunc("/api/endpoint", api.handleEndpoint).Methods("GET")
   ```

### Authentication

All API requests (except `/api/auth/login`) require JWT token:

```javascript
fetch('/api/beacons', {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    }
})
```

Token is stored in `localStorage` and automatically included by the dashboard.

## Security Considerations

- Always use HTTPS (TLS certificates required)
- JWT tokens expire after configured session timeout
- Change default admin password immediately after first deployment
- Consider implementing rate limiting for login attempts
- Use strong passwords for all operator accounts

## Browser Compatibility

Tested and working on:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

Requires JavaScript enabled.

## Future Enhancements

- [ ] Task creation interface
- [ ] Real-time WebSocket updates
- [ ] Beacon command console
- [ ] Task history and results viewer
- [ ] Operator management interface
- [ ] Audit log viewer
- [ ] Multi-language support
- [ ] Dark/light theme toggle
