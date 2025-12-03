/**
 * Unkn0wnC2 Shared JavaScript Library
 * Common utilities and WebSocket management for all pages
 */

// ===========================================
// Configuration
// ===========================================
const CONFIG = {
    WS_RECONNECT_INTERVAL: 3000,
    WS_MAX_RECONNECT_ATTEMPTS: 10,
    ONLINE_THRESHOLD: 600, // 10 minutes in seconds - matches server-side logic
    TOAST_DURATION: 5000,
};

// ===========================================
// WebSocket Manager
// ===========================================
class WebSocketManager {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.handlers = new Map();
        this.isConnected = false;
        this.statusElement = null;
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        try {
            this.socket = new WebSocket(wsUrl);
            this.updateStatus('connecting');

            this.socket.onopen = () => {
                console.log('[WS] Connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.updateStatus('connected');
                this.emit('connected');
            };

            this.socket.onclose = (event) => {
                console.log('[WS] Disconnected:', event.code, event.reason);
                this.isConnected = false;
                this.updateStatus('disconnected');
                this.emit('disconnected');
                this.scheduleReconnect();
            };

            this.socket.onerror = (error) => {
                console.error('[WS] Error:', error);
                this.updateStatus('disconnected');
            };

            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (e) {
                    console.error('[WS] Failed to parse message:', e);
                }
            };
        } catch (error) {
            console.error('[WS] Connection failed:', error);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= CONFIG.WS_MAX_RECONNECT_ATTEMPTS) {
            console.warn('[WS] Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = CONFIG.WS_RECONNECT_INTERVAL * Math.min(this.reconnectAttempts, 5);
        console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

        setTimeout(() => this.connect(), delay);
    }

    updateStatus(status) {
        if (!this.statusElement) {
            this.statusElement = document.getElementById('wsStatus');
        }
        if (this.statusElement) {
            const dot = this.statusElement.querySelector('.ws-status-dot');
            const text = this.statusElement.querySelector('.ws-status-text');
            if (dot) {
                dot.className = `ws-status-dot ${status}`;
            }
            if (text) {
                text.textContent = status === 'connected' ? 'Live' : 
                                   status === 'connecting' ? 'Connecting...' : 'Offline';
            }
        }
    }

    handleMessage(data) {
        const { type, payload } = data;
        
        // Emit to specific handlers
        if (this.handlers.has(type)) {
            this.handlers.get(type).forEach(handler => handler(payload));
        }

        // Emit to wildcard handlers
        if (this.handlers.has('*')) {
            this.handlers.get('*').forEach(handler => handler(type, payload));
        }
    }

    on(event, handler) {
        if (!this.handlers.has(event)) {
            this.handlers.set(event, []);
        }
        this.handlers.get(event).push(handler);
    }

    off(event, handler) {
        if (this.handlers.has(event)) {
            const handlers = this.handlers.get(event);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    emit(event, data) {
        if (this.handlers.has(event)) {
            this.handlers.get(event).forEach(handler => handler(data));
        }
    }

    send(type, payload) {
        if (this.isConnected && this.socket) {
            this.socket.send(JSON.stringify({ type, payload }));
        }
    }
}

// Global WebSocket instance
const ws = new WebSocketManager();



// ===========================================
// API Utilities
// ===========================================
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

async function authFetch(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    // Add CSRF token for state-changing requests
    if (options.method && options.method !== 'GET') {
        const csrfToken = getCookie('csrf_token');
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
    }

    try {
        const response = await fetch(url, {
            ...options,
            headers,
            credentials: 'include'
        });

        if (response.status === 401 || response.status === 403) {
            window.location.href = '/login';
            return null;
        }

        return response;
    } catch (error) {
        console.error('Fetch error:', error);
        showToast('Network error. Please check your connection.', 'error');
        return null;
    }
}

// ===========================================
// Formatting Utilities
// ===========================================
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    if (minutes < 60) {
        return remainingSeconds > 0 ? `${minutes}m ${remainingSeconds}s` : `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
}

function formatRate(bytesPerSecond) {
    return formatBytes(bytesPerSecond) + '/s';
}

function isOnline(timestamp) {
    if (!timestamp) return false;
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    return diff < CONFIG.ONLINE_THRESHOLD;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===========================================
// UI Utilities
// ===========================================
function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.add('show');
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.remove('show');
}

function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button class="close-btn" onclick="this.parentElement.remove()">×</button>
    `;
    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, CONFIG.TOAST_DURATION);
}

function showAlert(message, type = 'success') {
    const container = document.getElementById('alertContainer');
    if (!container) {
        showToast(message, type);
        return;
    }

    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    container.innerHTML = '';
    container.appendChild(alert);

    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, CONFIG.TOAST_DURATION);
}

function showModal(title, content, footer = null) {
    let overlay = document.getElementById('modalOverlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'modalOverlay';
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3 class="modal-title"></h3>
                    <button class="modal-close" onclick="hideModal()">×</button>
                </div>
                <div class="modal-body"></div>
                <div class="modal-footer"></div>
            </div>
        `;
        document.body.appendChild(overlay);
    }

    overlay.querySelector('.modal-title').textContent = title;
    overlay.querySelector('.modal-body').innerHTML = content;
    overlay.querySelector('.modal-footer').innerHTML = footer || '';
    overlay.classList.add('show');
}

function hideModal() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) {
        overlay.classList.remove('show');
    }
}

// ===========================================
// Bulk Selection Manager
// ===========================================
class BulkSelectionManager {
    constructor(tableId, actionBarId) {
        this.tableId = tableId;
        this.actionBarId = actionBarId;
        this.selectedIds = new Set();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        const table = document.getElementById(this.tableId);
        if (!table) return;

        // Select all checkbox
        const selectAllCheckbox = table.querySelector('th input[type="checkbox"]');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                const checkboxes = table.querySelectorAll('td input[type="checkbox"]');
                checkboxes.forEach(cb => {
                    cb.checked = e.target.checked;
                    this.updateSelection(cb.value, e.target.checked);
                });
                this.updateActionBar();
            });
        }

        // Individual checkboxes
        table.addEventListener('change', (e) => {
            if (e.target.type === 'checkbox' && e.target.closest('td')) {
                this.updateSelection(e.target.value, e.target.checked);
                this.updateActionBar();
            }
        });
    }

    updateSelection(id, selected) {
        if (selected) {
            this.selectedIds.add(id);
        } else {
            this.selectedIds.delete(id);
        }
    }

    updateActionBar() {
        const actionBar = document.getElementById(this.actionBarId);
        if (!actionBar) return;

        if (this.selectedIds.size > 0) {
            actionBar.classList.add('show');
            const countEl = actionBar.querySelector('.selected-count');
            if (countEl) {
                countEl.textContent = `${this.selectedIds.size} selected`;
            }
        } else {
            actionBar.classList.remove('show');
        }
    }

    getSelected() {
        return Array.from(this.selectedIds);
    }

    clearSelection() {
        this.selectedIds.clear();
        const table = document.getElementById(this.tableId);
        if (table) {
            table.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.checked = false;
            });
        }
        this.updateActionBar();
    }
}

// ===========================================
// Logout Function
// ===========================================
async function logout() {
    try {
        await authFetch('/api/auth/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }
    window.location.href = '/login';
}

// ===========================================
// Initialize on DOM Ready
// ===========================================
document.addEventListener('DOMContentLoaded', () => {
    // Initialize WebSocket if not on login page
    if (!window.location.pathname.includes('/login')) {
        ws.connect();
    }

    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Escape to close modals
        if (e.key === 'Escape') {
            hideModal();
        }
        
        // R to refresh (when not in input)
        if (e.key === 'r' && !e.ctrlKey && !e.metaKey && 
            !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
            const refreshBtn = document.querySelector('.btn-refresh');
            if (refreshBtn) refreshBtn.click();
        }
    });
});

// Export for module usage if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ws,
        authFetch,
        formatTimestamp,
        formatBytes,
        formatDuration,
        formatRate,
        isOnline,
        escapeHtml,
        showLoading,
        hideLoading,
        showToast,
        showAlert,
        showModal,
        hideModal,
        logout,
        BulkSelectionManager
    };
}
