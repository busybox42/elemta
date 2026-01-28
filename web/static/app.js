// Elemta MTA Dashboard - Application JavaScript

// ============================================================================
// State Management
// ============================================================================
const state = {
    currentQueue: 'active',
    currentPage: 1,
    pageSize: 25,
    allMessages: [],
    filteredMessages: [],
    selectedMessages: new Set(),
    currentMessageId: null,
    refreshInterval: null,
    refreshRate: 30000
};

// ============================================================================
// API Configuration
// ============================================================================
const API_BASE = '/api';

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    initializeNavigation();
    initializeEventListeners();
    loadFromURL();
    refreshAllData();
    startAutoRefresh();
});

// ============================================================================
// Theme Management
// ============================================================================
function initializeTheme() {
    const savedTheme = localStorage.getItem('elemta-theme') || 'dark';
    setTheme(savedTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('elemta-theme', theme);

    // Update theme option buttons
    document.querySelectorAll('.theme-option').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.theme === theme);
    });
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    setTheme(currentTheme === 'dark' ? 'light' : 'dark');
}

// ============================================================================
// Navigation
// ============================================================================
function initializeNavigation() {
    // View navigation
    document.querySelectorAll('.nav-item[data-view]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });

    // View All links
    document.querySelectorAll('.view-all[data-view]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });

    // Sidebar toggle
    document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('collapsed');
    });

    // Mobile menu toggle
    document.getElementById('mobile-menu-toggle')?.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });

    // Theme toggle
    document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);

    // Queue tabs
    document.querySelectorAll('.queue-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            switchQueue(tab.dataset.queue);
        });
    });

    // Modal tabs
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            switchModalTab(tab.dataset.tab);
        });
    });

    // Close sidebar on backdrop click (mobile)
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('sidebar');
        if (sidebar.classList.contains('open') &&
            !sidebar.contains(e.target) &&
            e.target !== document.getElementById('mobile-menu-toggle')) {
            sidebar.classList.remove('open');
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
}

function switchView(viewName) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Update views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.toggle('active', view.id === `view-${viewName}`);
    });

    // Update page title
    const titles = {
        dashboard: 'Dashboard',
        queues: 'Mail Queues',
        logs: 'Logs',
        settings: 'Settings'
    };
    document.getElementById('page-title').textContent = titles[viewName] || viewName;

    // Close mobile sidebar
    document.getElementById('sidebar').classList.remove('open');

    // Load view-specific data
    if (viewName === 'queues') {
        loadQueue(state.currentQueue);
    } else if (viewName === 'logs') {
        refreshLogs();
    }
}

// ============================================================================
// Event Listeners
// ============================================================================
function initializeEventListeners() {
    // Search input
    const searchInput = document.getElementById('search-input');
    let searchTimeout;
    searchInput?.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            state.currentPage = 1;
            applyFilters();
            updateURL();
        }, 300);
    });

    // Filter selects
    ['priority-filter', 'date-filter'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', () => {
            state.currentPage = 1;
            applyFilters();
            updateURL();
        });
    });

    // Page size
    document.getElementById('page-size')?.addEventListener('change', (e) => {
        state.pageSize = parseInt(e.target.value);
        state.currentPage = 1;
        applyFilters();
        updateURL();
    });

    // Refresh interval
    document.getElementById('refresh-interval')?.addEventListener('change', (e) => {
        state.refreshRate = parseInt(e.target.value);
        startAutoRefresh();
    });
}

// ============================================================================
// URL State Management
// ============================================================================
function updateURL() {
    const params = new URLSearchParams();
    params.set('queue', state.currentQueue);
    params.set('page', state.currentPage.toString());
    params.set('pageSize', state.pageSize.toString());

    const searchTerm = document.getElementById('search-input')?.value;
    if (searchTerm) params.set('search', searchTerm);

    const priorityFilter = document.getElementById('priority-filter')?.value;
    if (priorityFilter) params.set('priority', priorityFilter);

    const dateFilter = document.getElementById('date-filter')?.value;
    if (dateFilter) params.set('date', dateFilter);

    window.history.replaceState({}, '', `?${params.toString()}`);
}

function loadFromURL() {
    const params = new URLSearchParams(window.location.search);

    const queueParam = params.get('queue');
    if (queueParam && ['active', 'deferred', 'hold', 'failed'].includes(queueParam)) {
        state.currentQueue = queueParam;
    }

    state.currentPage = parseInt(params.get('page')) || 1;
    state.pageSize = parseInt(params.get('pageSize')) || 25;

    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = params.get('search') || '';

    const priorityFilter = document.getElementById('priority-filter');
    if (priorityFilter) priorityFilter.value = params.get('priority') || '';

    const dateFilter = document.getElementById('date-filter');
    if (dateFilter) dateFilter.value = params.get('date') || '';

    const pageSize = document.getElementById('page-size');
    if (pageSize) pageSize.value = state.pageSize.toString();

    // Update queue tabs
    document.querySelectorAll('.queue-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.queue === state.currentQueue);
    });
}

// ============================================================================
// Data Loading
// ============================================================================
async function refreshAllData() {
    showRefreshIndicator(true);
    try {
        await Promise.all([
            loadQueueStats(),
            loadQueue(state.currentQueue),
            loadRecentActivity()
        ]);
        updateLastUpdated();
    } catch (error) {
        console.error('Error refreshing data:', error);
    } finally {
        showRefreshIndicator(false);
    }
}

async function loadQueueStats() {
    try {
        const response = await fetch(`${API_BASE}/queue/stats`);
        const stats = await response.json();

        document.getElementById('stat-active').textContent = stats.active_count || 0;
        document.getElementById('stat-deferred').textContent = stats.deferred_count || 0;
        document.getElementById('stat-hold').textContent = stats.hold_count || 0;
        document.getElementById('stat-failed').textContent = stats.failed_count || 0;

        document.getElementById('badge-active').textContent = stats.active_count || 0;
        document.getElementById('badge-deferred').textContent = stats.deferred_count || 0;
        document.getElementById('badge-hold').textContent = stats.hold_count || 0;
        document.getElementById('badge-failed').textContent = stats.failed_count || 0;
    } catch (error) {
        console.error('Error loading queue stats:', error);
    }
}

async function loadQueue(queueType) {
    showRefreshIndicator(true);
    try {
        const response = await fetch(`${API_BASE}/queue/${queueType}`);
        const messages = await response.json();

        state.allMessages = messages || [];
        state.filteredMessages = [...state.allMessages];
        state.selectedMessages.clear();

        applyFilters();
    } catch (error) {
        console.error('Error loading queue:', error);
        showToast('Failed to load queue data', 'error');
        document.getElementById('messages-tbody').innerHTML =
            '<tr><td colspan="9" class="loading-cell">Failed to load messages</td></tr>';
    } finally {
        showRefreshIndicator(false);
    }
}

async function loadRecentActivity() {
    try {
        const response = await fetch(`${API_BASE}/queue/active`);
        const messages = await response.json();

        const container = document.getElementById('recent-activity');
        if (!messages || messages.length === 0) {
            container.innerHTML = '<div class="loading-placeholder">No recent activity</div>';
            return;
        }

        const recentMessages = messages.slice(0, 5);
        container.innerHTML = recentMessages.map(msg => `
            <div class="activity-item">
                <div class="activity-icon queued">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${escapeHtml(msg.subject || 'No Subject')}</div>
                    <div class="activity-meta">${escapeHtml(msg.from || 'Unknown')} • ${formatTimeAgo(msg.created_at)}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

// ============================================================================
// Queue Management
// ============================================================================
function switchQueue(queue) {
    state.currentQueue = queue;
    state.currentPage = 1;
    state.selectedMessages.clear();

    // Update tabs
    document.querySelectorAll('.queue-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.queue === queue);
    });

    // Clear filters
    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
    const priorityFilter = document.getElementById('priority-filter');
    if (priorityFilter) priorityFilter.value = '';
    const dateFilter = document.getElementById('date-filter');
    if (dateFilter) dateFilter.value = '';

    updateURL();
    loadQueue(queue);
}

function refreshQueue() {
    loadQueueStats();
    loadQueue(state.currentQueue);
}

async function retryCurrentQueue() {
    if (!confirm(`Retry all messages in the ${state.currentQueue} queue?\n\nThis will attempt immediate delivery.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/queue/${state.currentQueue}/flush`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast(`${state.currentQueue} queue retry initiated`, 'success');
            refreshQueue();
        } else {
            throw new Error('Retry failed');
        }
    } catch (error) {
        showToast('Failed to retry queue', 'error');
    }
}

async function retryQueue(queueType) {
    try {
        const response = await fetch(`${API_BASE}/queue/${queueType}/flush`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast(`${queueType} queue processing started`, 'success');
            refreshAllData();
        } else {
            throw new Error('Retry failed');
        }
    } catch (error) {
        showToast('Failed to process queue', 'error');
    }
}

async function retryAllQueues() {
    if (!confirm('Retry ALL messages in ALL queues?\n\nThis is a system-wide operation.')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/queue/all/flush`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast('All queues retry initiated', 'success');
            refreshAllData();
        } else {
            throw new Error('Retry failed');
        }
    } catch (error) {
        showToast('Failed to retry all queues', 'error');
    }
}

// ============================================================================
// Filtering & Pagination
// ============================================================================
function applyFilters() {
    const searchTerm = document.getElementById('search-input')?.value.toLowerCase() || '';
    const priorityFilter = document.getElementById('priority-filter')?.value || '';
    const dateFilter = document.getElementById('date-filter')?.value || '';

    state.filteredMessages = state.allMessages.filter(message => {
        // Search filter
        if (searchTerm) {
            const searchableText = [
                message.id || '',
                message.from || '',
                Array.isArray(message.to) ? message.to.join(' ') : message.to || '',
                message.subject || ''
            ].join(' ').toLowerCase();

            if (!searchableText.includes(searchTerm)) {
                return false;
            }
        }

        // Priority filter
        if (priorityFilter && message.priority != priorityFilter) {
            return false;
        }

        // Date filter
        if (dateFilter) {
            const messageDate = new Date(message.created_at);
            const now = new Date();
            let cutoffDate;

            switch (dateFilter) {
                case '1h':
                    cutoffDate = new Date(now.getTime() - 60 * 60 * 1000);
                    break;
                case '24h':
                    cutoffDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                    break;
                case '7d':
                    cutoffDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    break;
                case '30d':
                    cutoffDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    break;
            }

            if (cutoffDate && messageDate < cutoffDate) {
                return false;
            }
        }

        return true;
    });

    renderMessages();
    updateBatchActions();
}

function renderMessages() {
    const tbody = document.getElementById('messages-tbody');
    const totalMessages = state.filteredMessages.length;
    const totalPages = Math.ceil(totalMessages / state.pageSize);

    if (state.currentPage > totalPages && totalPages > 0) {
        state.currentPage = totalPages;
    }

    const startIndex = (state.currentPage - 1) * state.pageSize;
    const endIndex = startIndex + state.pageSize;
    const pageMessages = state.filteredMessages.slice(startIndex, endIndex);

    if (pageMessages.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="loading-cell">No messages found</td></tr>';
        document.getElementById('pagination-info').textContent = '0 messages';
        document.getElementById('pagination-controls').innerHTML = '';
        return;
    }

    tbody.innerHTML = pageMessages.map(msg => {
        const isSelected = state.selectedMessages.has(msg.id);
        const priority = getPriorityLabel(msg.priority);
        const toList = Array.isArray(msg.to) ? msg.to.join(', ') : msg.to;

        return `
            <tr class="${isSelected ? 'selected' : ''}">
                <td class="checkbox-col">
                    <input type="checkbox" 
                           onchange="toggleMessageSelection('${msg.id}')"
                           ${isSelected ? 'checked' : ''}>
                </td>
                <td><span class="message-id">${escapeHtml(msg.id?.substring(0, 12) || '')}</span></td>
                <td title="${escapeHtml(msg.from || '')}">${escapeHtml(msg.from || 'Unknown')}</td>
                <td title="${escapeHtml(toList || '')}">${escapeHtml(toList || 'Unknown')}</td>
                <td title="${escapeHtml(msg.subject || '')}">${escapeHtml(msg.subject || 'No Subject')}</td>
                <td><span class="priority-badge priority-${priority.toLowerCase()}">${priority}</span></td>
                <td>${formatDate(msg.created_at)}</td>
                <td><span class="status-badge status-${state.currentQueue}">${state.currentQueue}</span></td>
                <td>
                    <div class="action-buttons">
                        <button onclick="viewMessage('${msg.id}')" title="View Details">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                        </button>
                        <button onclick="retryMessage('${msg.id}')" title="Retry">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="23 4 23 10 17 10"/>
                                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                            </svg>
                        </button>
                        <button onclick="deleteMessage('${msg.id}')" title="Delete">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    // Update pagination
    const start = startIndex + 1;
    const end = Math.min(endIndex, totalMessages);
    document.getElementById('pagination-info').textContent =
        `Showing ${start}-${end} of ${totalMessages} messages`;

    renderPagination(totalPages);
}

function renderPagination(totalPages) {
    const controls = document.getElementById('pagination-controls');

    if (totalPages <= 1) {
        controls.innerHTML = '';
        return;
    }

    let html = '';

    // Previous button
    html += `<button onclick="goToPage(${state.currentPage - 1})" ${state.currentPage === 1 ? 'disabled' : ''}>‹</button>`;

    // Page numbers
    let startPage = Math.max(1, state.currentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);

    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }

    if (startPage > 1) {
        html += `<button onclick="goToPage(1)">1</button>`;
        if (startPage > 2) html += '<span style="padding: 0 0.5rem;">...</span>';
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<button onclick="goToPage(${i})" class="${i === state.currentPage ? 'active' : ''}">${i}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += '<span style="padding: 0 0.5rem;">...</span>';
        html += `<button onclick="goToPage(${totalPages})">${totalPages}</button>`;
    }

    // Next button
    html += `<button onclick="goToPage(${state.currentPage + 1})" ${state.currentPage === totalPages ? 'disabled' : ''}>›</button>`;

    controls.innerHTML = html;
}

function goToPage(page) {
    const totalPages = Math.ceil(state.filteredMessages.length / state.pageSize);
    if (page < 1 || page > totalPages) return;

    state.currentPage = page;
    updateURL();
    renderMessages();
}

// ============================================================================
// Message Selection
// ============================================================================
function toggleMessageSelection(messageId) {
    if (state.selectedMessages.has(messageId)) {
        state.selectedMessages.delete(messageId);
    } else {
        state.selectedMessages.add(messageId);
    }
    updateBatchActions();
}

function toggleSelectAll() {
    const selectAll = document.getElementById('select-all');
    const startIndex = (state.currentPage - 1) * state.pageSize;
    const endIndex = startIndex + state.pageSize;
    const pageMessages = state.filteredMessages.slice(startIndex, endIndex);

    if (selectAll.checked) {
        pageMessages.forEach(msg => state.selectedMessages.add(msg.id));
    } else {
        pageMessages.forEach(msg => state.selectedMessages.delete(msg.id));
    }

    renderMessages();
    updateBatchActions();
}

function clearSelection() {
    state.selectedMessages.clear();
    document.getElementById('select-all').checked = false;
    renderMessages();
    updateBatchActions();
}

function updateBatchActions() {
    const batchActions = document.getElementById('batch-actions');
    const selectedCount = document.getElementById('selected-count');

    if (state.selectedMessages.size > 0) {
        batchActions.style.display = 'flex';
        selectedCount.textContent = state.selectedMessages.size;
    } else {
        batchActions.style.display = 'none';
    }
}

async function deleteSelected() {
    if (!confirm(`Delete ${state.selectedMessages.size} selected messages?\n\nThis cannot be undone.`)) {
        return;
    }

    let successCount = 0;
    for (const id of state.selectedMessages) {
        try {
            const response = await fetch(`${API_BASE}/queue/message/${id}`, { method: 'DELETE' });
            if (response.ok) successCount++;
        } catch (error) {
            console.error(`Failed to delete ${id}:`, error);
        }
    }

    showToast(`Deleted ${successCount} of ${state.selectedMessages.size} messages`, 'success');
    clearSelection();
    refreshQueue();
}

async function retrySelected() {
    showToast(`Retrying ${state.selectedMessages.size} messages...`, 'info');
    clearSelection();
    await retryCurrentQueue();
}

// ============================================================================
// Message Actions
// ============================================================================
async function viewMessage(messageId) {
    state.currentMessageId = messageId;

    const modal = document.getElementById('message-modal');
    const modalBody = document.getElementById('modal-body');

    modal.classList.add('active');
    modalBody.innerHTML = '<div class="loading-placeholder">Loading message...</div>';

    // Reset tabs
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === 'details');
    });

    try {
        const response = await fetch(`${API_BASE}/queue/message/${messageId}`);
        const message = await response.json();

        state.currentMessage = message;
        renderMessageDetails(message);
    } catch (error) {
        modalBody.innerHTML = '<div class="loading-placeholder">Failed to load message</div>';
    }
}

function renderMessageDetails(message) {
    const modalBody = document.getElementById('modal-body');
    const toList = Array.isArray(message.to) ? message.to.join(', ') : message.to;

    modalBody.innerHTML = `
        <dl class="message-detail-grid">
            <dt>Message ID</dt>
            <dd>${escapeHtml(message.id || 'Unknown')}</dd>
            
            <dt>From</dt>
            <dd>${escapeHtml(message.from || 'Unknown')}</dd>
            
            <dt>To</dt>
            <dd>${escapeHtml(toList || 'Unknown')}</dd>
            
            <dt>Subject</dt>
            <dd>${escapeHtml(message.subject || 'No Subject')}</dd>
            
            <dt>Priority</dt>
            <dd>${getPriorityLabel(message.priority)}</dd>
            
            <dt>Created</dt>
            <dd>${formatDate(message.created_at)}</dd>
            
            <dt>Retry Count</dt>
            <dd>${message.retry_count || 0}</dd>
            
            ${message.last_error ? `
                <dt>Last Error</dt>
                <dd style="color: var(--accent-danger);">${escapeHtml(message.last_error)}</dd>
            ` : ''}
            
            ${message.next_retry_at ? `
                <dt>Next Retry</dt>
                <dd>${formatDate(message.next_retry_at)}</dd>
            ` : ''}
        </dl>
    `;
}

function switchModalTab(tab) {
    document.querySelectorAll('.modal-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tab);
    });

    const modalBody = document.getElementById('modal-body');
    const message = state.currentMessage;

    if (!message) return;

    switch (tab) {
        case 'details':
            renderMessageDetails(message);
            break;
        case 'headers':
            const headers = parseMessageHeaders(message.content);
            modalBody.innerHTML = `<pre class="message-content-raw">${escapeHtml(headers || 'No headers available')}</pre>`;
            break;
        case 'raw':
            modalBody.innerHTML = `<pre class="message-content-raw">${escapeHtml(message.content || 'No content available')}</pre>`;
            break;
    }
}

function closeModal() {
    document.getElementById('message-modal').classList.remove('active');
    state.currentMessageId = null;
    state.currentMessage = null;
}

async function retryMessage(messageId) {
    showToast('Retrying message...', 'info');
    await retryCurrentQueue();
}

async function deleteMessage(messageId) {
    if (!confirm('Delete this message?\n\nThis cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/queue/message/${messageId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('Message deleted', 'success');
            refreshQueue();
            closeModal();
        } else {
            throw new Error('Delete failed');
        }
    } catch (error) {
        showToast('Failed to delete message', 'error');
    }
}

function retryCurrentMessage() {
    if (state.currentMessageId) {
        retryMessage(state.currentMessageId);
    }
}

function deleteCurrentMessage() {
    if (state.currentMessageId) {
        deleteMessage(state.currentMessageId);
    }
}

// ============================================================================
// Logs
// ============================================================================
async function refreshLogs() {
    const container = document.getElementById('logs-container');
    const levelFilter = document.getElementById('log-level-filter')?.value || '';
    const typeFilter = document.getElementById('log-type-filter')?.value || '';
    const searchTerm = document.getElementById('log-search-input')?.value.toLowerCase() || '';

    try {
        // Build query parameters
        const params = new URLSearchParams();
        params.set('limit', '200');
        if (typeFilter) params.set('event_type', typeFilter);
        if (levelFilter) params.set('level', levelFilter);

        const response = await fetch(`${API_BASE}/logs/messages?${params.toString()}`);
        if (!response.ok) throw new Error('Failed to fetch logs');

        const data = await response.json();

        if (!data.logs || data.logs.length === 0) {
            container.innerHTML = '<div class="log-entry info"><span class="log-message">No logs available</span></div>';
            return;
        }

        let logs = data.logs;

        // Apply search filter
        if (searchTerm) {
            logs = logs.filter(log => {
                const searchable = [
                    log.msg,
                    log.component,
                    log.event_type,
                    JSON.stringify(log.fields)
                ].join(' ').toLowerCase();
                return searchable.includes(searchTerm);
            });
        }

        if (logs.length === 0) {
            container.innerHTML = '<div class="log-entry info"><span class="log-message">No logs match your filters</span></div>';
            return;
        }

        // Render logs as a table
        container.innerHTML = `
            <table class="logs-table">
                <thead>
                    <tr>
                        <th width="140">Time</th>
                        <th width="80">Level</th>
                        <th width="120">Type</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    ${logs.map(log => {
            const time = log.time ? new Date(log.time).toLocaleString() : 'Unknown';
            const level = (log.level || 'INFO').toUpperCase();
            const eventType = log.event_type || log.component || '-';
            const eventTypeClass = getEventTypeClass(log.event_type);

            return `
                        <tr class="log-row ${level.toLowerCase()}">
                            <td class="log-time-cell">${escapeHtml(time)}</td>
                            <td><span class="log-level-badge ${level.toLowerCase()}">${level}</span></td>
                            <td><span class="log-type-badge ${eventTypeClass}">${escapeHtml(eventType)}</span></td>
                            <td class="log-message-cell">
                                <div class="log-msg-text">${escapeHtml(log.msg || '')}</div>
                                ${renderLogFields(log.fields)}
                            </td>
                        </tr>
                        `;
        }).join('')}
                </tbody>
            </table>
        `;

    } catch (error) {
        console.error('Error fetching logs:', error);
        container.innerHTML = '<div class="log-entry error"><span class="log-message">Failed to load logs</span></div>';
        showToast('Failed to load logs', 'error');
    }
}

function getEventTypeClass(eventType) {
    const typeMap = {
        'reception': 'event-reception',
        'delivery': 'event-delivery',
        'rejection': 'event-rejection',
        'deferral': 'event-deferral',
        'bounce': 'event-bounce',
        'tempfail': 'event-tempfail',
        'authentication': 'event-auth'
    };
    return typeMap[eventType] || 'event-system';
}

function renderLogFields(fields) {
    if (!fields || Object.keys(fields).length === 0) return '';

    const items = Object.entries(fields).map(([key, value]) => {
        // Skip internal/noisy fields
        if (key === 'caller' || key === 'stack') return '';

        let displayValue = value;
        if (typeof value === 'object') {
            displayValue = JSON.stringify(value);
        }

        // Highlight specific keys
        let className = 'log-ctx-val';
        if (key === 'error' || key === 'rejection_reason' || key === 'deferral_reason' || key === 'bounce_reason') {
            className += ' ctx-error';
        }
        if (key === 'message_id' || key === 'queue_id') {
            className += ' ctx-id';
        }
        if (key === 'from' || key === 'to' || key === 'recipient_count') {
            className += ' ctx-email';
        }
        if (key === 'client_ip' || key === 'remote_addr') {
            className += ' ctx-ip';
        }

        return `<span class="log-ctx-item"><span class="log-ctx-key">${escapeHtml(key)}:</span> <span class="${className}">${escapeHtml(String(displayValue))}</span></span>`;
    }).filter(item => item !== '').join('');

    return items ? `<div class="log-context">${items}</div>` : '';
}

function parseLogLine(line) {
    // Try to parse JSON log format
    try {
        const json = JSON.parse(line);
        const message = json.msg || '';
        const level = json.level || 'INFO';
        const time = json.time ? new Date(json.time).toLocaleString() : 'Unknown';
        const component = json.component || '';

        // Extract context fields (everything except standard fields)
        const context = { ...json };
        delete context.msg;
        delete context.level;
        delete context.time;
        delete context.component;

        // Filter out empty context
        if (Object.keys(context).length === 0) {
            return { time, level, component, message, context: null };
        }

        return { time, level, component, message, context };
    } catch {
        // Fallback for non-JSON logs
        const match = line.match(/^(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s*(\w+)?\s*(.*)$/);
        if (match) {
            return {
                time: match[1],
                level: match[2] || 'INFO',
                component: '',
                message: match[3] || line,
                context: null
            };
        }
        // Plain text log
        return {
            time: new Date().toLocaleString(),
            level: 'INFO',
            component: '',
            message: line,
            context: null
        };
    }
}

function getLogType(log) {
    const msg = log.message.toLowerCase();
    const comp = (log.component || '').toLowerCase();
    const ctx = log.context || {};
    const response = (ctx.response || '').toLowerCase();
    const error = (ctx.error || '').toLowerCase();
    const eventType = (ctx.event_type || '').toLowerCase();

    // Rejection (5xx) - Check explicit event_type first
    if (eventType === 'rejection' || msg.includes('reject') || msg.includes('denied') ||
        response.startsWith('5') || error.includes('554') || error.includes('550')) {
        return 'rejection';
    }

    // TempFail (4xx temporary failures) - Check explicit event_type first
    if (eventType === 'tempfail' || msg.includes('tempfail') || msg.includes('temporary failure') ||
        response.startsWith('4') || error.includes('451') || error.includes('421')) {
        return 'tempfail';
    }

    // Deferral - Check explicit event_type first
    if (eventType === 'deferral' || msg.includes('defer') || eventType === 'message_deferred') {
        return 'defer';
    }

    // Bounce
    if (eventType === 'bounce' || msg.includes('bounce') || msg.includes('bounced') || eventType === 'message_bounced') {
        return 'bounce';
    }

    // Auth - Check explicit event_type first
    if (eventType === 'authentication' || msg.includes('auth') || msg.includes('authentication') || comp.includes('auth')) {
        return 'auth';
    }

    // Delivery
    if (eventType === 'delivery' || msg.includes('delivered') || msg.includes('delivery successful') ||
        comp.includes('delivery') || comp.includes('sender') || eventType === 'message_delivered') {
        return 'delivery';
    }

    // Reception
    if (eventType === 'reception' || msg.includes('received') || msg.includes('accepted') || msg.includes('session created') ||
        comp.includes('smtp-session') || comp.includes('receiver') || eventType === 'message_received') {
        return 'reception';
    }

    // Queue
    if (msg.includes('queue') || comp.includes('queue') || eventType === 'message_accepted') {
        return 'queue';
    }

    // System (default fallback)
    return 'system';
}

function renderLogContext(context) {
    if (!context) return '';

    const fields = Object.entries(context).map(([key, value]) => {
        // Skip internal/noisy fields if needed
        if (key === 'caller' || key === 'stack') return '';

        let displayValue = value;
        if (typeof value === 'object') {
            displayValue = JSON.stringify(value);
        }

        // Highlight specific keys
        let className = 'log-ctx-val';
        if (key === 'error') className += ' ctx-error';
        if (key === 'message_id') className += ' ctx-id';
        if (key === 'email' || key === 'from' || key === 'to' || key === 'from_envelope' || key === 'to_envelope') className += ' ctx-email';
        if (key === 'remote_addr' || key === 'client_ip' || key === 'host' || key === 'server_ip') className += ' ctx-ip';

        return `<span class="log-ctx-item"><span class="log-ctx-key">${escapeHtml(key)}:</span> <span class="${className}">${escapeHtml(String(displayValue))}</span></span>`;
    }).join('');

    return fields ? `<div class="log-context">${fields}</div>` : '';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Settings
// ============================================================================
function updateRefreshInterval() {
    const select = document.getElementById('refresh-interval');
    state.refreshRate = parseInt(select.value);
    startAutoRefresh();
    showToast(`Auto-refresh set to ${select.options[select.selectedIndex].text}`, 'info');
}

function updateDefaultPageSize() {
    const select = document.getElementById('default-page-size');
    state.pageSize = parseInt(select.value);
    document.getElementById('page-size').value = select.value;
    state.currentPage = 1;
    applyFilters();
    showToast('Page size updated', 'info');
}

// ============================================================================
// Auto Refresh
// ============================================================================
function startAutoRefresh() {
    if (state.refreshInterval) {
        clearInterval(state.refreshInterval);
    }

    if (state.refreshRate > 0) {
        state.refreshInterval = setInterval(() => {
            loadQueueStats();
            loadQueue(state.currentQueue);
        }, state.refreshRate);
    }
}

function showRefreshIndicator(show) {
    const indicator = document.getElementById('refresh-indicator');
    indicator.classList.toggle('active', show);
}

function updateLastUpdated() {
    document.getElementById('last-updated').textContent = 'Updated just now';
}

// ============================================================================
// Toast Notifications
// ============================================================================
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');

    const iconSvg = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
        error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${iconSvg[type]}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"/>
                <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
        </button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ============================================================================
// Utility Functions
// ============================================================================
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function getPriorityLabel(priority) {
    switch (priority) {
        case 4: return 'Critical';
        case 3: return 'High';
        case 2: return 'Normal';
        case 1: return 'Low';
        default: return 'Normal';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleString();
}

function formatTimeAgo(dateString) {
    if (!dateString) return 'Unknown';

    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

function parseMessageHeaders(content) {
    if (!content) return '';

    const lines = content.split('\n');
    const headerLines = [];

    for (const line of lines) {
        if (line.trim() === '') break;
        headerLines.push(line);
    }

    return headerLines.join('\n');
}

// ============================================================================
// Authentication
// ============================================================================
const authState = {
    isLoggedIn: false,
    username: null,
    permissions: []
};

function showLoginModal() {
    document.getElementById('login-modal').classList.add('active');
    document.getElementById('user-dropdown').classList.remove('active');
    document.getElementById('login-username').focus();
}

function closeLoginModal() {
    document.getElementById('login-modal').classList.remove('active');
    document.getElementById('login-error').style.display = 'none';
}

async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            authState.isLoggedIn = true;
            authState.username = data.username;
            authState.permissions = data.permissions || [];
            updateUserUI();
            closeLoginModal();
            showToast(`Welcome, ${data.username}!`, 'success');
        } else {
            errorEl.textContent = 'Invalid username or password';
            errorEl.style.display = 'block';
        }
    } catch (error) {
        errorEl.textContent = 'Login failed. Server may be unavailable.';
        errorEl.style.display = 'block';
    }
}

async function handleLogout() {
    try {
        await fetch('/auth/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }

    authState.isLoggedIn = false;
    authState.username = null;
    authState.permissions = [];
    updateUserUI();
    document.getElementById('user-dropdown').classList.remove('active');
    showToast('Logged out successfully', 'info');
}

function updateUserUI() {
    const userDisplay = document.getElementById('user-display');
    const userInfoPanel = document.getElementById('user-info-panel');
    const userName = document.getElementById('user-name');
    const btnLogin = document.getElementById('btn-login');
    const btnLogout = document.getElementById('btn-logout');
    const btnApikeys = document.getElementById('btn-apikeys');

    if (authState.isLoggedIn) {
        userDisplay.textContent = authState.username;
        userName.textContent = authState.username;
        userInfoPanel.style.display = 'block';
        btnLogin.style.display = 'none';
        btnLogout.style.display = 'flex';
        btnApikeys.style.display = 'flex';
    } else {
        userDisplay.textContent = 'Guest';
        userInfoPanel.style.display = 'none';
        btnLogin.style.display = 'flex';
        btnLogout.style.display = 'none';
        btnApikeys.style.display = 'none';
    }
}

function toggleUserMenu() {
    const dropdown = document.getElementById('user-dropdown');
    dropdown.classList.toggle('active');
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const userMenu = document.getElementById('user-menu');
    const dropdown = document.getElementById('user-dropdown');
    if (userMenu && !userMenu.contains(e.target)) {
        dropdown.classList.remove('active');
    }
});

// ============================================================================
// API Keys
// ============================================================================
function showAPIKeysModal() {
    document.getElementById('apikeys-modal').classList.add('active');
    document.getElementById('user-dropdown').classList.remove('active');
    loadAPIKeys();
}

function closeAPIKeysModal() {
    document.getElementById('apikeys-modal').classList.remove('active');
}

async function loadAPIKeys() {
    const container = document.getElementById('apikey-list');

    try {
        const response = await fetch('/auth/apikeys');
        if (!response.ok) throw new Error('Failed to load API keys');

        const keys = await response.json();

        if (!keys || keys.length === 0) {
            container.innerHTML = '<div class="loading-placeholder">No API keys found</div>';
            return;
        }

        container.innerHTML = keys.map(key => `
            <div class="apikey-item">
                <div class="apikey-info">
                    <strong>${escapeHtml(key.name)}</strong>
                    <span class="apikey-desc">${escapeHtml(key.description || '')}</span>
                    <span class="apikey-meta">Created: ${formatDate(key.created_at)}</span>
                </div>
                <div class="apikey-actions">
                    <button class="btn btn-danger btn-sm" onclick="revokeAPIKey('${key.id}')">Revoke</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        container.innerHTML = '<div class="loading-placeholder">Failed to load API keys</div>';
    }
}

async function createAPIKey(event) {
    event.preventDefault();

    const name = document.getElementById('apikey-name').value;
    const description = document.getElementById('apikey-desc').value;
    const expiryDays = document.getElementById('apikey-expiry').value;

    try {
        const response = await fetch('/auth/apikeys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                description,
                expiry_days: expiryDays ? parseInt(expiryDays) : null
            })
        });

        if (response.ok) {
            const data = await response.json();
            showToast('API key created! Key: ' + data.key, 'success');
            document.getElementById('apikey-form').reset();
            loadAPIKeys();
        } else {
            showToast('Failed to create API key', 'error');
        }
    } catch (error) {
        showToast('Failed to create API key', 'error');
    }
}

async function revokeAPIKey(keyId) {
    if (!confirm('Revoke this API key? This cannot be undone.')) return;

    try {
        const response = await fetch(`/auth/apikeys/${keyId}/revoke`, { method: 'POST' });
        if (response.ok) {
            showToast('API key revoked', 'success');
            loadAPIKeys();
        } else {
            showToast('Failed to revoke API key', 'error');
        }
    } catch (error) {
        showToast('Failed to revoke API key', 'error');
    }
}

// ============================================================================
// Health Monitoring
// ============================================================================
async function refreshHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const health = await response.json();

        // Update status cards
        document.getElementById('health-status').textContent = health.status || 'Unknown';
        document.getElementById('health-uptime').textContent = health.uptime_formatted || '0s';
        document.getElementById('health-goroutines').textContent = health.num_goroutines || 0;
        document.getElementById('health-memory').textContent = (health.memory?.alloc_mb || 0).toFixed(1) + ' MB';

        // System info
        document.getElementById('health-go-version').textContent = health.go_version || '-';
        document.getElementById('health-server-version').textContent = health.server_version || '-';
        document.getElementById('health-cpus').textContent = health.num_cpu || '-';
        document.getElementById('health-listen-addr').textContent = health.configured_addr || '-';
        document.getElementById('health-auth-enabled').textContent = health.auth_enabled ? 'Yes' : 'No';
        document.getElementById('health-started-at').textContent = health.started_at ? formatDate(health.started_at) : '-';

        // Memory details
        const mem = health.memory || {};
        document.getElementById('mem-alloc').textContent = formatBytes(mem.alloc || 0);
        document.getElementById('mem-total-alloc').textContent = formatBytes(mem.total_alloc || 0);
        document.getElementById('mem-sys').textContent = formatBytes(mem.sys || 0);
        document.getElementById('mem-heap-inuse').textContent = formatBytes(mem.heap_inuse || 0);
        document.getElementById('mem-stack-inuse').textContent = formatBytes(mem.stack_inuse || 0);
        document.getElementById('mem-gc-cycles').textContent = mem.num_gc || 0;

        // Queue health
        const queue = health.queue || {};
        document.getElementById('queue-total').textContent = queue.total_messages || 0;
        document.getElementById('queue-active-health').textContent = queue.active_count || 0;
        document.getElementById('queue-deferred-health').textContent = queue.deferred_count || 0;
        document.getElementById('queue-hold-health').textContent = queue.hold_count || 0;
        document.getElementById('queue-failed-health').textContent = queue.failed_count || 0;
        document.getElementById('queue-processor').textContent = queue.processor_active ? 'Yes' : 'No';

        // Throughput
        const throughput = health.throughput || {};
        document.getElementById('throughput-per-min').textContent = (throughput.messages_per_minute || 0).toFixed(2);
        document.getElementById('throughput-per-hour').textContent = (throughput.messages_per_hour || 0).toFixed(2);
        document.getElementById('throughput-total').textContent = throughput.total_processed || 0;

        // SMTP
        const smtp = health.smtp || {};
        document.getElementById('smtp-connections').textContent = smtp.active_connections || 0;
        document.getElementById('smtp-total-connections').textContent = smtp.total_connections || 0;
        document.getElementById('smtp-tls').textContent = smtp.tls_enabled ? 'Yes' : 'No';

    } catch (error) {
        console.error('Error loading health:', error);
        showToast('Failed to load health data', 'error');
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// Compose / Send Test Email
// ============================================================================
const sendHistory = [];

async function sendTestEmail(event) {
    event.preventDefault();

    const from = document.getElementById('compose-from').value;
    const to = document.getElementById('compose-to').value;
    const subject = document.getElementById('compose-subject').value;
    const body = document.getElementById('compose-body').value;

    const sendBtn = document.getElementById('send-btn');
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span class="loading">Sending...</span>';

    try {
        const response = await fetch(`${API_BASE}/send-test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ from, to, subject, body })
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Test email queued successfully!', 'success');

            // Add to history
            sendHistory.unshift({
                id: data.message_id,
                from,
                to,
                subject,
                timestamp: new Date()
            });
            updateSendHistory();
        } else {
            showToast(data.error || 'Failed to send email', 'error');
        }
    } catch (error) {
        showToast('Failed to send email: ' + error.message, 'error');
    } finally {
        sendBtn.disabled = false;
        sendBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="22" y1="2" x2="11" y2="13"/>
                <polygon points="22 2 15 22 11 13 2 9 22 2"/>
            </svg>
            Send Test Email
        `;
    }
}

function clearComposeForm() {
    document.getElementById('compose-form').reset();
    document.getElementById('compose-subject').value = 'Test Email from Elemta';
    document.getElementById('compose-body').value = `This is a test email sent from the Elemta web interface.

If you received this message, your mail server is working correctly!`;
}

function updateSendHistory() {
    const container = document.getElementById('send-history');

    if (sendHistory.length === 0) {
        container.innerHTML = '<div class="loading-placeholder">No test emails sent yet</div>';
        return;
    }

    container.innerHTML = sendHistory.slice(0, 10).map(item => `
        <div class="activity-item">
            <div class="activity-icon sent">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"/>
                </svg>
            </div>
            <div class="activity-content">
                <div class="activity-title">${escapeHtml(item.subject)}</div>
                <div class="activity-meta">To: ${escapeHtml(item.to)} • ${formatTimeAgo(item.timestamp)}</div>
            </div>
        </div>
    `).join('');
}

// ============================================================================
// Reports / Delivery Statistics
// ============================================================================
let chartInstance = null;

async function refreshReports() {
    try {
        const response = await fetch(`${API_BASE}/stats/delivery`);
        const stats = await response.json();

        // Update stat cards
        document.getElementById('report-delivered').textContent = stats.total_delivered || 0;
        document.getElementById('report-failed').textContent = stats.total_failed || 0;
        document.getElementById('report-deferred').textContent = stats.total_deferred || 0;
        document.getElementById('report-success-rate').textContent = (stats.success_rate || 0).toFixed(1) + '%';

        // Update chart
        renderHourlyChart(stats.by_hour || []);

        // Update recent errors
        renderRecentErrors(stats.recent_errors || []);

    } catch (error) {
        console.error('Error loading reports:', error);
        showToast('Failed to load reports', 'error');
    }
}

function renderHourlyChart(hourlyData) {
    const canvas = document.getElementById('hourly-chart-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const container = canvas.parentElement;

    // Set canvas size
    canvas.width = container.offsetWidth;
    canvas.height = 200;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (hourlyData.length === 0) {
        ctx.fillStyle = 'var(--text-muted)';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data available', canvas.width / 2, canvas.height / 2);
        return;
    }

    // Simple bar chart
    const padding = 40;
    const barWidth = (canvas.width - padding * 2) / hourlyData.length - 4;
    const maxValue = Math.max(...hourlyData.map(h => h.delivered + h.failed + h.deferred), 1);
    const chartHeight = canvas.height - padding * 2;

    hourlyData.forEach((hour, i) => {
        const x = padding + i * (barWidth + 4);
        const total = hour.delivered + hour.failed + hour.deferred;
        const height = (total / maxValue) * chartHeight;

        // Stacked bars
        let y = canvas.height - padding;

        // Delivered (green)
        const deliveredHeight = (hour.delivered / maxValue) * chartHeight;
        ctx.fillStyle = '#22c55e';
        ctx.fillRect(x, y - deliveredHeight, barWidth, deliveredHeight);
        y -= deliveredHeight;

        // Deferred (orange)
        const deferredHeight = (hour.deferred / maxValue) * chartHeight;
        ctx.fillStyle = '#f59e0b';
        ctx.fillRect(x, y - deferredHeight, barWidth, deferredHeight);
        y -= deferredHeight;

        // Failed (red)
        const failedHeight = (hour.failed / maxValue) * chartHeight;
        ctx.fillStyle = '#ef4444';
        ctx.fillRect(x, y - failedHeight, barWidth, failedHeight);

        // Hour label
        if (i % 4 === 0) {
            ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted');
            ctx.font = '10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(hour.hour, x + barWidth / 2, canvas.height - padding + 15);
        }
    });

    // Legend
    ctx.font = '11px sans-serif';
    const legendY = 15;
    ctx.fillStyle = '#22c55e';
    ctx.fillRect(padding, legendY - 8, 12, 12);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-primary');
    ctx.textAlign = 'left';
    ctx.fillText('Delivered', padding + 16, legendY);

    ctx.fillStyle = '#f59e0b';
    ctx.fillRect(padding + 80, legendY - 8, 12, 12);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-primary');
    ctx.fillText('Deferred', padding + 96, legendY);

    ctx.fillStyle = '#ef4444';
    ctx.fillRect(padding + 160, legendY - 8, 12, 12);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-primary');
    ctx.fillText('Failed', padding + 176, legendY);
}

function renderRecentErrors(errors) {
    const container = document.getElementById('recent-errors');

    if (!errors || errors.length === 0) {
        container.innerHTML = '<div class="loading-placeholder">No recent errors</div>';
        return;
    }

    container.innerHTML = errors.map(err => `
        <div class="error-item">
            <div class="error-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
            </div>
            <div class="error-content">
                <div class="error-message">${escapeHtml(err.error)}</div>
                <div class="error-meta">${escapeHtml(err.recipient)} • ${formatTimeAgo(err.timestamp)}</div>
            </div>
        </div>
    `).join('');
}

// ============================================================================
// Enhanced Message Preview
// ============================================================================
function switchModalTab(tab) {
    document.querySelectorAll('.modal-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tab);
    });

    const modalBody = document.getElementById('modal-body');
    const message = state.currentMessage;

    if (!message) return;

    switch (tab) {
        case 'details':
            renderMessageDetails(message);
            break;
        case 'preview':
            renderMessagePreview(message);
            break;
        case 'headers':
            const headers = parseMessageHeaders(message.content);
            modalBody.innerHTML = `<pre class="message-content-raw">${escapeHtml(headers || 'No headers available')}</pre>`;
            break;
        case 'raw':
            modalBody.innerHTML = `<pre class="message-content-raw">${escapeHtml(message.content || 'No content available')}</pre>`;
            break;
    }
}

function renderMessagePreview(message) {
    const modalBody = document.getElementById('modal-body');
    const content = message.content || '';

    // Extract body from content
    const parts = content.split('\r\n\r\n');
    const body = parts.length > 1 ? parts.slice(1).join('\r\n\r\n') : content;

    // Check if HTML
    const isHtml = body.toLowerCase().includes('<html') || body.toLowerCase().includes('<body');

    if (isHtml) {
        modalBody.innerHTML = `
            <div class="preview-container">
                <div class="preview-warning">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    HTML content rendered in sandbox
                </div>
                <iframe class="preview-frame" sandbox="allow-same-origin" srcdoc="${escapeHtml(body).replace(/"/g, '&quot;')}"></iframe>
            </div>
        `;
    } else {
        modalBody.innerHTML = `
            <div class="preview-container">
                <pre class="preview-text">${escapeHtml(body)}</pre>
            </div>
        `;
    }
}

// ============================================================================
// Enhanced Log Level Control
// ============================================================================
async function getLogLevel() {
    try {
        const response = await fetch(`${API_BASE}/logging/level`);
        const data = await response.json();
        return data.level || 'info';
    } catch (error) {
        return 'info';
    }
}

async function setLogLevel(level) {
    try {
        const response = await fetch(`${API_BASE}/logging/level`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ level })
        });

        if (response.ok) {
            showToast(`Log level set to ${level}`, 'success');
        } else {
            showToast('Failed to set log level', 'error');
        }
    } catch (error) {
        showToast('Failed to set log level', 'error');
    }
}

// ============================================================================
// View-specific data loading
// ============================================================================
// Override switchView to load view-specific data
const originalSwitchView = switchView;
switchView = function (viewName) {
    // Call original
    const titles = {
        dashboard: 'Dashboard',
        health: 'Server Health',
        queues: 'Mail Queues',
        compose: 'Send Test Email',
        reports: 'Delivery Reports',
        logs: 'Logs',
        settings: 'Settings'
    };

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Update views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.toggle('active', view.id === `view-${viewName}`);
    });

    // Update page title
    document.getElementById('page-title').textContent = titles[viewName] || viewName;

    // Close mobile sidebar
    document.getElementById('sidebar').classList.remove('open');

    // Load view-specific data
    switch (viewName) {
        case 'health':
            refreshHealth();
            break;
        case 'queues':
            loadQueue(state.currentQueue);
            break;
        case 'reports':
            refreshReports();
            break;
        case 'logs':
            refreshLogs();
            break;
    }
};
