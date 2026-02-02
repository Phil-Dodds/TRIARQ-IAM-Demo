// ===== TRIARQ IAM Access Request Portal v3.1 =====
// Shared data via Supabase (no auth required for demo)

(function() {
    'use strict';

    // ===== Demo Users =====
    const DEMO_USERS = {
        jon: { id: 'jon', name: 'Jon', email: 'jon@triarqhealth.com', isIam: true, isAdmin: true },
        pintal: { id: 'pintal', name: 'Pintal', email: 'pintal@triarqhealth.com', isIam: true, isAdmin: false },
        ami: { id: 'ami', name: 'Ami', email: 'ami@triarqhealth.com', isIam: true, isAdmin: false },
        alice: { id: 'alice', name: 'Alice Johnson', email: 'alice@triarqhealth.com', isIam: false, isAdmin: false },
        bob: { id: 'bob', name: 'Bob Smith', email: 'bob@triarqhealth.com', isIam: false, isAdmin: false }
    };

    // ===== Constants =====
    const SLA_DAYS = 7;
    const SESSION_KEY = 'triarq_iam_session';

    const SYSTEMS = [
        'Okta / SSO',
        'Microsoft 365 / Exchange',
        'Azure AD',
        'VPN',
        'EMR',
        'Data Warehouse / BI',
        'GitHub',
        'Jira',
        'Shared Drive / SharePoint',
        'AWS Console',
        'Other'
    ];

    const ENVIRONMENTS = ['Prod', 'Non-Prod', 'Both'];
    const REQUEST_TYPES = ['Add', 'Remove', 'Change Role', 'Other'];
    const URGENCIES = ['Low', 'Normal', 'High'];
    const STATUSES = ['New', 'In Review', 'Need Info', 'Declined', 'Completed'];

    // ===== State =====
    let state = {
        currentUser: null,
        requests: [],
        currentView: null,
        filters: {
            status: '',
            urgency: '',
            search: ''
        }
    };

    // ===== Session Management =====
    function saveSession(user) {
        localStorage.setItem(SESSION_KEY, JSON.stringify(user));
    }

    function loadSession() {
        try {
            const data = localStorage.getItem(SESSION_KEY);
            return data ? JSON.parse(data) : null;
        } catch {
            return null;
        }
    }

    function clearSession() {
        localStorage.removeItem(SESSION_KEY);
    }

    // ===== Utility Functions =====
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatDate(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    function formatDateShort(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
    }

    function isOverSLA(request) {
        if (['Completed', 'Declined'].includes(request.status)) return false;
        const createdAt = new Date(request.created_at);
        const now = new Date();
        const diffDays = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24));
        return diffDays > SLA_DAYS;
    }

    function getStatusClass(status) {
        const classes = {
            'New': 'status-new',
            'In Review': 'status-review',
            'Need Info': 'status-need-info',
            'Declined': 'status-declined',
            'Completed': 'status-completed'
        };
        return classes[status] || '';
    }

    function getUrgencyClass(urgency) {
        const classes = {
            'Low': 'urgency-low',
            'Normal': 'urgency-normal',
            'High': 'urgency-high'
        };
        return classes[urgency] || '';
    }

    // ===== Toast Notifications =====
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // ===== Screen Management =====
    function showScreen(screenId) {
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.add('hidden');
        });
        document.getElementById(screenId).classList.remove('hidden');
    }

    // ===== Modal Management =====
    function showModal(content, options = {}) {
        const overlay = document.getElementById('modal-overlay');
        const container = document.getElementById('modal-container');

        container.innerHTML = content;
        container.className = 'modal-container' + (options.wide ? ' modal-wide' : '');
        overlay.classList.remove('hidden');

        overlay.onclick = (e) => {
            if (e.target === overlay && !options.preventClose) {
                closeModal();
            }
        };
    }

    function closeModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }

    // ===== Permission Checks =====
    function isIamUser() {
        return state.currentUser && (state.currentUser.isIam || state.currentUser.isAdmin);
    }

    function isAdmin() {
        return state.currentUser && state.currentUser.isAdmin;
    }

    function canViewAllRequests() {
        return isIamUser();
    }

    // ===== Auth Functions =====
    function initLoginForm() {
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();

            const userId = document.getElementById('login-user').value;
            const errorDiv = document.getElementById('login-error');

            if (!userId) {
                errorDiv.textContent = 'Please select a user';
                errorDiv.classList.remove('hidden');
                return;
            }

            const user = DEMO_USERS[userId];
            if (!user) {
                errorDiv.textContent = 'Invalid user';
                errorDiv.classList.remove('hidden');
                return;
            }

            state.currentUser = user;
            saveSession(user);
            errorDiv.classList.add('hidden');
            initMainApp();
        });
    }

    function handleSignOut() {
        state.currentUser = null;
        state.requests = [];
        clearSession();
        supabaseUnsubscribeFromRequests();
        showScreen('login-screen');
        document.getElementById('login-user').value = '';
        showToast('Signed out successfully', 'success');
    }

    // ===== Data Loading =====
    async function loadRequests() {
        try {
            const requests = await supabaseGetRequests();
            state.requests = requests;
            return requests;
        } catch (error) {
            console.error('Failed to load requests:', error);
            showToast('Failed to load requests', 'error');
            return [];
        }
    }

    // ===== Header & Navigation =====
    function updateHeader() {
        const identitySpan = document.getElementById('user-identity');
        const badgesSpan = document.getElementById('role-badges');

        if (state.currentUser) {
            identitySpan.textContent = state.currentUser.name;

            let badges = '';
            if (state.currentUser.isAdmin) {
                badges += '<span class="role-badge badge-admin">Admin</span>';
            }
            if (state.currentUser.isIam) {
                badges += '<span class="role-badge badge-iam">IAM</span>';
            }
            if (!state.currentUser.isIam && !state.currentUser.isAdmin) {
                badges += '<span class="role-badge badge-employee">Employee</span>';
            }
            badgesSpan.innerHTML = badges;
        }
    }

    function renderNav() {
        const nav = document.getElementById('app-nav');
        let navItems = '';

        navItems += `
            <a href="#" class="nav-item" data-view="new-request">New Request</a>
            <a href="#" class="nav-item" data-view="my-requests">My Requests</a>
        `;

        if (canViewAllRequests()) {
            navItems += `<a href="#" class="nav-item" data-view="dashboard">Dashboard</a>`;
        }

        nav.innerHTML = navItems;

        nav.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                navigateTo(e.target.dataset.view);
            });
        });
    }

    function navigateTo(view) {
        state.currentView = view;

        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.view === view);
        });

        const mainContent = document.getElementById('app-main');

        switch (view) {
            case 'new-request':
                renderNewRequestForm(mainContent);
                break;
            case 'my-requests':
                renderMyRequests(mainContent);
                break;
            case 'dashboard':
                if (canViewAllRequests()) {
                    renderDashboard(mainContent);
                } else {
                    navigateTo('my-requests');
                }
                break;
            default:
                navigateTo('new-request');
        }
    }

    // ===== New Request Form =====
    function renderNewRequestForm(container) {
        const systemOptions = SYSTEMS.map(s =>
            `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`
        ).join('');

        const envOptions = ENVIRONMENTS.map(e =>
            `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`
        ).join('');

        const typeOptions = REQUEST_TYPES.map(t =>
            `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`
        ).join('');

        const urgencyOptions = URGENCIES.map(u =>
            `<option value="${escapeHtml(u)}" ${u === 'Normal' ? 'selected' : ''}>${escapeHtml(u)}</option>`
        ).join('');

        container.innerHTML = `
            <div class="form-container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Submit New Access Request</h2>
                    </div>
                    <div class="card-body">
                        <form id="new-request-form">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="req-name">Your Name</label>
                                    <input type="text" class="form-control" id="req-name"
                                           value="${escapeHtml(state.currentUser.name)}" readonly>
                                </div>
                                <div class="form-group">
                                    <label for="req-email">Your Email</label>
                                    <input type="text" class="form-control" id="req-email"
                                           value="${escapeHtml(state.currentUser.email)}" readonly>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="req-department">Department / Team *</label>
                                <input type="text" class="form-control" id="req-department" required>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="req-system">Application / System *</label>
                                    <select class="form-control" id="req-system" required>${systemOptions}</select>
                                </div>
                                <div class="form-group" id="other-system-group" style="display: none;">
                                    <label for="req-other-system">Specify System *</label>
                                    <input type="text" class="form-control" id="req-other-system">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="req-environment">Environment *</label>
                                    <select class="form-control" id="req-environment" required>${envOptions}</select>
                                </div>
                                <div class="form-group">
                                    <label for="req-type">Request Type *</label>
                                    <select class="form-control" id="req-type" required>${typeOptions}</select>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="req-role">Requested Role / Permission *</label>
                                <input type="text" class="form-control" id="req-role" required
                                       placeholder="e.g., Read-only access, Admin role, etc.">
                            </div>
                            <div class="form-group">
                                <label for="req-justification">Business Justification *</label>
                                <textarea class="form-control" id="req-justification" required
                                          placeholder="Explain why you need this access..."></textarea>
                            </div>
                            <div class="form-group">
                                <label for="req-urgency">Urgency</label>
                                <select class="form-control" id="req-urgency">${urgencyOptions}</select>
                            </div>
                            <div class="form-actions">
                                <button type="submit" class="btn btn-primary">Submit Request</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('req-system').addEventListener('change', (e) => {
            const otherGroup = document.getElementById('other-system-group');
            const otherInput = document.getElementById('req-other-system');
            if (e.target.value === 'Other') {
                otherGroup.style.display = 'block';
                otherInput.required = true;
            } else {
                otherGroup.style.display = 'none';
                otherInput.required = false;
            }
        });

        document.getElementById('new-request-form').addEventListener('submit', handleNewRequestSubmit);
    }

    async function handleNewRequestSubmit(e) {
        e.preventDefault();

        const form = e.target;
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        const system = document.getElementById('req-system').value;
        const otherSystem = document.getElementById('req-other-system').value.trim();

        if (system === 'Other' && !otherSystem) {
            showToast('Please specify the system name', 'error');
            return;
        }

        const request = {
            requester_id: state.currentUser.id,
            requester_name: state.currentUser.name,
            requester_email: state.currentUser.email,
            department: document.getElementById('req-department').value.trim(),
            application_or_system: system,
            application_other_text: system === 'Other' ? otherSystem : null,
            environment: document.getElementById('req-environment').value,
            request_type: document.getElementById('req-type').value,
            requested_role_or_permission: document.getElementById('req-role').value.trim(),
            justification: document.getElementById('req-justification').value.trim(),
            urgency: document.getElementById('req-urgency').value,
            status: 'New'
        };

        try {
            const created = await supabaseCreateRequest(request);

            await supabaseAddRequestEvent({
                request_id: created.id,
                actor_id: state.currentUser.id,
                actor_name: state.currentUser.name,
                actor_email: state.currentUser.email,
                event_type: 'created',
                new_value: 'New',
                comment: 'Request submitted'
            });

            showToast('Request submitted successfully!', 'success');
            await loadRequests();
            navigateTo('my-requests');
        } catch (error) {
            console.error('Failed to submit request:', error);
            showToast('Failed to submit request', 'error');
        }
    }

    // ===== My Requests =====
    function renderMyRequests(container) {
        const myRequests = state.requests
            .filter(r => r.requester_id === state.currentUser.id)
            .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));

        const statusOptions = ['', ...STATUSES].map(s =>
            `<option value="${escapeHtml(s)}">${s || 'All Statuses'}</option>`
        ).join('');

        container.innerHTML = `
            <div class="list-header">
                <h2 class="list-title">My Requests</h2>
                <div class="list-filters">
                    <input type="text" class="form-control search-input" id="my-search" placeholder="Search requests...">
                    <select class="form-control" id="my-status-filter">${statusOptions}</select>
                </div>
            </div>
            <div class="card">
                <div class="card-body" style="padding: 0;">
                    <div id="my-requests-list"></div>
                </div>
            </div>
        `;

        renderMyRequestsList(myRequests);

        document.getElementById('my-search').addEventListener('input', () => filterMyRequests());
        document.getElementById('my-status-filter').addEventListener('change', () => filterMyRequests());
    }

    function filterMyRequests() {
        const search = document.getElementById('my-search').value.toLowerCase();
        const status = document.getElementById('my-status-filter').value;

        let filtered = state.requests.filter(r => r.requester_id === state.currentUser.id);

        if (status) {
            filtered = filtered.filter(r => r.status === status);
        }

        if (search) {
            filtered = filtered.filter(r => {
                const searchStr = `${r.request_number} ${r.application_or_system} ${r.department}`.toLowerCase();
                return searchStr.includes(search);
            });
        }

        filtered.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
        renderMyRequestsList(filtered);
    }

    function renderMyRequestsList(requests) {
        const listContainer = document.getElementById('my-requests-list');

        if (requests.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <p>No requests found</p>
                </div>
            `;
            return;
        }

        listContainer.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>System</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Urgency</th>
                        <th>Updated</th>
                    </tr>
                </thead>
                <tbody>
                    ${requests.map(r => `
                        <tr class="clickable-row" data-id="${r.id}">
                            <td><strong>${escapeHtml(r.request_number)}</strong></td>
                            <td>${escapeHtml(r.application_or_system === 'Other' ? r.application_other_text : r.application_or_system)}</td>
                            <td>${escapeHtml(r.request_type)}</td>
                            <td><span class="status-badge ${getStatusClass(r.status)}">${escapeHtml(r.status)}</span></td>
                            <td><span class="urgency-badge ${getUrgencyClass(r.urgency)}">${escapeHtml(r.urgency)}</span></td>
                            <td>${formatDateShort(r.updated_at)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        listContainer.querySelectorAll('.clickable-row').forEach(row => {
            row.addEventListener('click', () => showRequestDetail(row.dataset.id));
        });
    }

    // ===== Dashboard (IAM View) =====
    function renderDashboard(container) {
        const stats = {
            total: state.requests.length,
            new: state.requests.filter(r => r.status === 'New').length,
            inReview: state.requests.filter(r => r.status === 'In Review').length,
            needInfo: state.requests.filter(r => r.status === 'Need Info').length,
            overdue: state.requests.filter(r => isOverSLA(r)).length
        };

        const statusOptions = ['', ...STATUSES].map(s =>
            `<option value="${escapeHtml(s)}" ${state.filters.status === s ? 'selected' : ''}>
                ${s || 'All Statuses'}
            </option>`
        ).join('');

        const urgencyOptions = ['', ...URGENCIES].map(u =>
            `<option value="${escapeHtml(u)}" ${state.filters.urgency === u ? 'selected' : ''}>
                ${u || 'All Urgencies'}
            </option>`
        ).join('');

        container.innerHTML = `
            <div class="dashboard-stats">
                <div class="stat-card">
                    <div class="stat-number">${stats.total}</div>
                    <div class="stat-label">Total Requests</div>
                </div>
                <div class="stat-card stat-new">
                    <div class="stat-number">${stats.new}</div>
                    <div class="stat-label">New</div>
                </div>
                <div class="stat-card stat-review">
                    <div class="stat-number">${stats.inReview}</div>
                    <div class="stat-label">In Review</div>
                </div>
                <div class="stat-card stat-info">
                    <div class="stat-number">${stats.needInfo}</div>
                    <div class="stat-label">Need Info</div>
                </div>
                <div class="stat-card stat-overdue">
                    <div class="stat-number">${stats.overdue}</div>
                    <div class="stat-label">Overdue (>${SLA_DAYS}d)</div>
                </div>
            </div>

            <div class="list-header">
                <h2 class="list-title">All Requests</h2>
                <div class="list-filters">
                    <input type="text" class="form-control search-input" id="dash-search"
                           placeholder="Search..." value="${escapeHtml(state.filters.search)}">
                    <select class="form-control" id="dash-status">${statusOptions}</select>
                    <select class="form-control" id="dash-urgency">${urgencyOptions}</select>
                </div>
            </div>

            <div class="card">
                <div class="card-body" style="padding: 0;">
                    <div id="dashboard-list"></div>
                </div>
            </div>
        `;

        renderDashboardList();

        document.getElementById('dash-search').addEventListener('input', (e) => {
            state.filters.search = e.target.value.toLowerCase();
            renderDashboardList();
        });

        document.getElementById('dash-status').addEventListener('change', (e) => {
            state.filters.status = e.target.value;
            renderDashboardList();
        });

        document.getElementById('dash-urgency').addEventListener('change', (e) => {
            state.filters.urgency = e.target.value;
            renderDashboardList();
        });
    }

    function renderDashboardList() {
        const listContainer = document.getElementById('dashboard-list');
        let filtered = [...state.requests];

        if (state.filters.status) {
            filtered = filtered.filter(r => r.status === state.filters.status);
        }
        if (state.filters.urgency) {
            filtered = filtered.filter(r => r.urgency === state.filters.urgency);
        }
        if (state.filters.search) {
            filtered = filtered.filter(r => {
                const searchStr = `${r.request_number} ${r.requester_name} ${r.requester_email} ${r.application_or_system} ${r.department}`.toLowerCase();
                return searchStr.includes(state.filters.search);
            });
        }

        filtered.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));

        if (filtered.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <p>No requests match the filters</p>
                </div>
            `;
            return;
        }

        listContainer.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Requester</th>
                        <th>System</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Urgency</th>
                        <th>SLA</th>
                        <th>Updated</th>
                    </tr>
                </thead>
                <tbody>
                    ${filtered.map(r => `
                        <tr class="clickable-row" data-id="${r.id}">
                            <td><strong>${escapeHtml(r.request_number)}</strong></td>
                            <td>${escapeHtml(r.requester_name)}</td>
                            <td>${escapeHtml(r.application_or_system === 'Other' ? r.application_other_text : r.application_or_system)}</td>
                            <td>${escapeHtml(r.request_type)}</td>
                            <td><span class="status-badge ${getStatusClass(r.status)}">${escapeHtml(r.status)}</span></td>
                            <td><span class="urgency-badge ${getUrgencyClass(r.urgency)}">${escapeHtml(r.urgency)}</span></td>
                            <td>${isOverSLA(r) ? '<span class="sla-warning">!</span>' : '-'}</td>
                            <td>${formatDateShort(r.updated_at)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        listContainer.querySelectorAll('.clickable-row').forEach(row => {
            row.addEventListener('click', () => showRequestDetail(row.dataset.id));
        });
    }

    // ===== Request Detail Modal =====
    async function showRequestDetail(requestId) {
        const request = state.requests.find(r => r.id === requestId);
        if (!request) {
            showToast('Request not found', 'error');
            return;
        }

        let events = [];
        try {
            events = await supabaseGetRequestEvents(requestId);
        } catch (error) {
            console.error('Failed to load events:', error);
        }

        const isOwner = request.requester_id === state.currentUser.id;
        const canEdit = isIamUser();
        const canComment = canEdit || (isOwner && request.status === 'Need Info');

        const statusOptions = STATUSES.map(s =>
            `<option value="${escapeHtml(s)}" ${request.status === s ? 'selected' : ''}>${escapeHtml(s)}</option>`
        ).join('');

        const modalContent = `
            <div class="modal-header">
                <h2>${escapeHtml(request.request_number)}</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="detail-grid">
                    <div class="detail-section">
                        <h3>Request Details</h3>
                        <div class="detail-item">
                            <span class="detail-label">Requester</span>
                            <span class="detail-value">${escapeHtml(request.requester_name)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Email</span>
                            <span class="detail-value">${escapeHtml(request.requester_email)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Department</span>
                            <span class="detail-value">${escapeHtml(request.department)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">System</span>
                            <span class="detail-value">${escapeHtml(request.application_or_system === 'Other' ? request.application_other_text : request.application_or_system)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Environment</span>
                            <span class="detail-value">${escapeHtml(request.environment)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Request Type</span>
                            <span class="detail-value">${escapeHtml(request.request_type)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Requested Role/Permission</span>
                            <span class="detail-value">${escapeHtml(request.requested_role_or_permission)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Justification</span>
                            <span class="detail-value">${escapeHtml(request.justification)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Urgency</span>
                            <span class="detail-value"><span class="urgency-badge ${getUrgencyClass(request.urgency)}">${escapeHtml(request.urgency)}</span></span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created</span>
                            <span class="detail-value">${formatDate(request.created_at)}</span>
                        </div>
                    </div>

                    <div class="detail-section">
                        <h3>Status & Assignment</h3>
                        ${canEdit ? `
                            <div class="form-group">
                                <label>Status</label>
                                <select class="form-control" id="detail-status">${statusOptions}</select>
                            </div>
                            <div class="form-group">
                                <label>Assignee</label>
                                <input type="text" class="form-control" id="detail-assignee"
                                       value="${escapeHtml(request.iam_assignee_name || '')}"
                                       placeholder="Enter assignee name">
                            </div>
                        ` : `
                            <div class="detail-item">
                                <span class="detail-label">Status</span>
                                <span class="detail-value"><span class="status-badge ${getStatusClass(request.status)}">${escapeHtml(request.status)}</span></span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Assignee</span>
                                <span class="detail-value">${escapeHtml(request.iam_assignee_name || 'Unassigned')}</span>
                            </div>
                        `}

                        <h3 style="margin-top: 24px;">Activity</h3>
                        <div class="activity-list">
                            ${events.length === 0 ? '<p class="text-muted">No activity yet</p>' :
                              events.map(event => `
                                <div class="activity-item">
                                    <div class="activity-header">
                                        <strong>${escapeHtml(event.actor_name)}</strong>
                                        <span class="activity-time">${formatDate(event.created_at)}</span>
                                    </div>
                                    <div class="activity-content">
                                        ${formatEventDescription(event)}
                                    </div>
                                </div>
                              `).join('')}
                        </div>

                        ${canComment ? `
                            <h3 style="margin-top: 24px;">Add Comment</h3>
                            <div class="form-group">
                                <textarea class="form-control" id="detail-comment"
                                          placeholder="Enter your comment..."></textarea>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Close</button>
                ${canEdit || canComment ? `
                    <button class="btn btn-primary" id="save-detail-btn">Save Changes</button>
                ` : ''}
            </div>
        `;

        showModal(modalContent, { wide: true });
        window.closeModal = closeModal;

        const saveBtn = document.getElementById('save-detail-btn');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => saveRequestChanges(request));
        }
    }

    function formatEventDescription(event) {
        switch (event.event_type) {
            case 'created':
                return 'Created request';
            case 'status_changed':
                return `Changed status from <strong>${escapeHtml(event.old_value)}</strong> to <strong>${escapeHtml(event.new_value)}</strong>`;
            case 'assigned':
                return `Assigned to <strong>${escapeHtml(event.new_value || 'Unassigned')}</strong>`;
            case 'comment_added':
            case 'comment_employee':
                return `<div class="comment-text">${escapeHtml(event.comment)}</div>`;
            default:
                return escapeHtml(event.event_type);
        }
    }

    async function saveRequestChanges(request) {
        const canEdit = isIamUser();
        const updates = {};
        const eventsToAdd = [];

        if (canEdit) {
            const newStatus = document.getElementById('detail-status')?.value;
            const newAssignee = document.getElementById('detail-assignee')?.value.trim();

            if (newStatus && newStatus !== request.status) {
                updates.status = newStatus;
                eventsToAdd.push({
                    request_id: request.id,
                    actor_id: state.currentUser.id,
                    actor_name: state.currentUser.name,
                    actor_email: state.currentUser.email,
                    event_type: 'status_changed',
                    old_value: request.status,
                    new_value: newStatus
                });
            }

            if (newAssignee !== (request.iam_assignee_name || '')) {
                updates.iam_assignee_name = newAssignee || null;
                updates.iam_assignee_id = newAssignee ? state.currentUser.id : null;
                eventsToAdd.push({
                    request_id: request.id,
                    actor_id: state.currentUser.id,
                    actor_name: state.currentUser.name,
                    actor_email: state.currentUser.email,
                    event_type: 'assigned',
                    old_value: request.iam_assignee_name,
                    new_value: newAssignee || null
                });
            }
        }

        const comment = document.getElementById('detail-comment')?.value.trim();
        if (comment) {
            eventsToAdd.push({
                request_id: request.id,
                actor_id: state.currentUser.id,
                actor_name: state.currentUser.name,
                actor_email: state.currentUser.email,
                event_type: canEdit ? 'comment_added' : 'comment_employee',
                comment: comment
            });
        }

        if (Object.keys(updates).length === 0 && eventsToAdd.length === 0) {
            showToast('No changes to save', 'info');
            return;
        }

        try {
            if (Object.keys(updates).length > 0) {
                await supabaseUpdateRequest(request.id, updates);
            }

            for (const event of eventsToAdd) {
                await supabaseAddRequestEvent(event);
            }

            showToast('Changes saved!', 'success');
            await loadRequests();
            closeModal();

            if (state.currentView === 'dashboard') {
                renderDashboard(document.getElementById('app-main'));
            } else if (state.currentView === 'my-requests') {
                renderMyRequests(document.getElementById('app-main'));
            }
        } catch (error) {
            console.error('Failed to save changes:', error);
            showToast('Failed to save changes', 'error');
        }
    }

    // ===== Realtime Updates =====
    function setupRealtimeSubscription() {
        supabaseSubscribeToRequests(async (payload) => {
            console.log('Realtime update:', payload);
            await loadRequests();

            const mainContent = document.getElementById('app-main');
            if (state.currentView === 'dashboard' && canViewAllRequests()) {
                renderDashboard(mainContent);
            } else if (state.currentView === 'my-requests') {
                renderMyRequests(mainContent);
            }

            showToast('Data updated', 'info');
        });
    }

    // ===== Main App Init =====
    async function initMainApp() {
        showScreen('main-app');
        updateHeader();
        renderNav();
        await loadRequests();
        setupRealtimeSubscription();

        if (canViewAllRequests()) {
            navigateTo('dashboard');
        } else {
            navigateTo('new-request');
        }
    }

    // ===== App Initialization =====
    async function init() {
        console.log('TRIARQ IAM Portal v3.1 - Demo Mode (No Auth)');

        // Check for existing session
        const savedUser = loadSession();
        if (savedUser && DEMO_USERS[savedUser.id]) {
            state.currentUser = DEMO_USERS[savedUser.id];
            await initMainApp();
        } else {
            showScreen('login-screen');
        }

        initLoginForm();
        document.getElementById('logout-btn').addEventListener('click', handleSignOut);
    }

    document.addEventListener('DOMContentLoaded', init);

})();
