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
    FETCH_TIMEOUT: 30000, // 30 second timeout for API requests
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
            console.warn('[WS] Max reconnection attempts reached, retrying in 60s');
            this.updateStatus('disconnected');
            setTimeout(() => {
                this.reconnectAttempts = 0;
                this.connect();
            }, 60000);
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

    // AbortController with configurable timeout
    const controller = new AbortController();
    const timeout = options.timeout || CONFIG.FETCH_TIMEOUT;
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            ...options,
            headers,
            credentials: 'include',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401) {
            window.location.href = '/login';
            return null;
        }

        if (response.status === 403) {
            showToast('Access denied. Insufficient permissions.', 'error');
            return null;
        }

        if (response.status >= 500) {
            showToast(`Server error (${response.status}). Try again later.`, 'error');
        }

        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            showToast('Request timed out. Server may be unreachable.', 'error');
        } else {
            console.error('Fetch error:', error);
            showToast('Network error. Please check your connection.', 'error');
        }
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

function formatAbsoluteTimestamp(timestamp) {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
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
    if (text == null) return '';
    const str = String(text);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function debounce(fn, delay) {
    let timer;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
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

const icons = {
    trash: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M216,52H40a4,4,0,0,0,0,8H52V208a12,12,0,0,0,12,12H192a12,12,0,0,0,12-12V60h12a4,4,0,0,0,0-8ZM196,208a4,4,0,0,1-4,4H64a4,4,0,0,1-4-4V60H196ZM84,24a4,4,0,0,1,4-4h80a4,4,0,0,1,0,8H88A4,4,0,0,1,84,24Z"/></svg>',
    xCircle: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M162.83,98.83,133.66,128l29.17,29.17a4,4,0,0,1-5.66,5.66L128,133.66,98.83,162.83a4,4,0,0,1-5.66-5.66L122.34,128,93.17,98.83a4,4,0,0,1,5.66-5.66L128,122.34l29.17-29.17a4,4,0,1,1,5.66,5.66ZM228,128A100,100,0,1,1,128,28,100.11,100.11,0,0,1,228,128Zm-8,0a92,92,0,1,0-92,92A92.1,92.1,0,0,0,220,128Z"/></svg>',
    copy: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M216,36H88a4,4,0,0,0-4,4V84H40a4,4,0,0,0-4,4V216a4,4,0,0,0,4,4H168a4,4,0,0,0,4-4V172h44a4,4,0,0,0,4-4V40A4,4,0,0,0,216,36ZM164,212H44V92H164Zm48-48H172V88a4,4,0,0,0-4-4H92V44H212Z"/></svg>',
    listDashes: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256" fill="currentColor"><path d="M92,64a4,4,0,0,1,4-4H216a4,4,0,0,1,0,8H96A4,4,0,0,1,92,64Zm124,60H96a4,4,0,0,0,0,8H216a4,4,0,0,0,0-8Zm0,64H96a4,4,0,0,0,0,8H216a4,4,0,0,0,0-8ZM56,60H40a4,4,0,0,0,0,8H56a4,4,0,0,0,0-8Zm0,64H40a4,4,0,0,0,0,8H56a4,4,0,0,0,0-8Zm0,64H40a4,4,0,0,0,0,8H56a4,4,0,0,0,0-8Z"/></svg>',
    warning: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256" fill="currentColor"><path d="M233.34,190.09,145.88,38.22h0a20.75,20.75,0,0,0-35.76,0L22.66,190.09a19.52,19.52,0,0,0,0,19.71A20.36,20.36,0,0,0,40.54,220H215.46a20.36,20.36,0,0,0,17.86-10.2A19.52,19.52,0,0,0,233.34,190.09ZM226.4,205.8a12.47,12.47,0,0,1-10.94,6.2H40.54a12.47,12.47,0,0,1-10.94-6.2,11.45,11.45,0,0,1,0-11.72L117.05,42.21a12.76,12.76,0,0,1,21.9,0L226.4,194.08A11.45,11.45,0,0,1,226.4,205.8ZM124,144V104a4,4,0,0,1,8,0v40a4,4,0,0,1-8,0Zm12,36a8,8,0,1,1-8-8A8,8,0,0,1,136,180Z"/></svg>',
    check: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M226.83,74.83l-128,128a4,4,0,0,1-5.66,0l-56-56a4,4,0,0,1,5.66-5.66L96,194.34,221.17,69.17a4,4,0,1,1,5.66,5.66Z"/></svg>',
    arrowUp: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M202.83,114.83a4,4,0,0,1-5.66,0L132,49.66V216a4,4,0,0,1-8,0V49.66L58.83,114.83a4,4,0,0,1-5.66-5.66l72-72a4,4,0,0,1,5.66,0l72,72A4,4,0,0,1,202.83,114.83Z"/></svg>',
    arrowDown: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M202.83,146.83l-72,72a4,4,0,0,1-5.66,0l-72-72a4,4,0,0,1,5.66-5.66L124,206.34V40a4,4,0,0,1,8,0V206.34l65.17-65.17a4,4,0,0,1,5.66,5.66Z"/></svg>',
    dotsThree: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256" fill="currentColor"><path d="M136,128a8,8,0,1,1-8-8A8,8,0,0,1,136,128Zm-76-8a8,8,0,1,0,8,8A8,8,0,0,0,60,120Zm136,0a8,8,0,1,0,8,8A8,8,0,0,0,196,120Z"/></svg>',
    shield: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 256 256" fill="currentColor"><path d="M208,44H48A12,12,0,0,0,36,56v56c0,51.16,24.73,82.12,45.47,99.1,22.4,18.32,44.55,24.5,45.48,24.76a4,4,0,0,0,2.1,0c.93-.26,23.08-6.44,45.48-24.76,20.74-17,45.47-47.94,45.47-99.1V56A12,12,0,0,0,208,44Zm4,68c0,38.44-14.23,69.63-42.29,92.71A132.45,132.45,0,0,1,128,227.82a132.23,132.23,0,0,1-41.71-23.11C58.23,181.63,44,150.44,44,112V56a4,4,0,0,1,4-4H208a4,4,0,0,1,4,4Z"/></svg>',
    globe: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 256 256" fill="currentColor"><path d="M128,28h0A100,100,0,1,0,228,128,100.11,100.11,0,0,0,128,28Zm91.66,64h-45a129.39,129.39,0,0,0-29.19-55.4A92.25,92.25,0,0,1,219.66,92ZM128,218.61c-6.33-6.09-23-24.41-31.27-54.61h62.54C151,194.2,134.33,212.52,128,218.61ZM94.82,156a140.42,140.42,0,0,1,0-56h66.36a140.42,140.42,0,0,1,0,56ZM36.34,100h46.25a152.65,152.65,0,0,0,0,56H36.34a92.09,92.09,0,0,1,0-56ZM128,37.39c6.33,6.09,23,24.41,31.27,54.61H96.73C105,61.8,121.67,43.48,128,37.39ZM173.41,100h46.23a92.09,92.09,0,0,1,0,56H173.41a152.65,152.65,0,0,0,0-56ZM36.34,164h45a129.39,129.39,0,0,0,29.19,55.4A92.25,92.25,0,0,1,36.34,164Zm102.12,55.4A129.39,129.39,0,0,0,167.65,164h45A92.25,92.25,0,0,1,138.46,219.4Z"/></svg>',
    terminal: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 256 256" fill="currentColor"><path d="M116,128a4,4,0,0,1-1.34,3l-72,64a4,4,0,1,1-5.32-6L106,128,37.34,67a4,4,0,0,1,5.32-6l72,64A4,4,0,0,1,116,128Zm100,60H120a4,4,0,0,0,0,8h96a4,4,0,0,0,0-8Z"/></svg>',
};

function icon(name, size) {
    const svg = icons[name];
    if (!svg || !size) return svg || '';
    return svg.replace(/width="\d+"/, `width="${size}"`).replace(/height="\d+"/, `height="${size}"`);
}

// Export for module usage if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ws,
        authFetch,
        formatTimestamp,
        formatAbsoluteTimestamp,
        formatBytes,
        formatDuration,
        formatRate,
        isOnline,
        escapeHtml,
        debounce,
        showLoading,
        hideLoading,
        showToast,
        showAlert,
        showModal,
        hideModal,
        logout,
        BulkSelectionManager,
        icons,
        icon
    };
}
