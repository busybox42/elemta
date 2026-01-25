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
function refreshLogs() {
    // Placeholder - implement when logs API is available
    showToast('Logs refreshed', 'info');
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
