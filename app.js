// ===== TRIARQ IAM Access Request Portal v3.2 =====
// Original UI preserved, Supabase backend for shared data

(function() {
    'use strict';

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

    // Demo Users (no auth required)
    const DEMO_USERS = {
        jon: { userId: 'jon', name: 'Jon', email: 'jon@triarqhealth.com', isIam: true, isAdmin: true, defaultDepartment: 'IT' },
        pintal: { userId: 'pintal', name: 'Pintal', email: 'pintal@triarqhealth.com', isIam: true, isAdmin: false, defaultDepartment: 'IT' },
        ami: { userId: 'ami', name: 'Ami', email: 'ami@triarqhealth.com', isIam: true, isAdmin: false, defaultDepartment: 'IT' },
        alice: { userId: 'alice', name: 'Alice Johnson', email: 'alice@triarqhealth.com', isIam: false, isAdmin: false, defaultDepartment: 'Engineering' },
        bob: { userId: 'bob', name: 'Bob Smith', email: 'bob@triarqhealth.com', isIam: false, isAdmin: false, defaultDepartment: 'Finance' }
    };

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

    // ===== Field Mapping (Supabase snake_case <-> App camelCase) =====
    function mapRequestFromDb(dbRow) {
        return {
            id: dbRow.request_number,
            dbId: dbRow.id,
            createdAt: dbRow.created_at,
            updatedAt: dbRow.updated_at,
            requesterUserId: dbRow.requester_id,
            requesterName: dbRow.requester_name,
            requesterEmail: dbRow.requester_email,
            department: dbRow.department,
            applicationOrSystem: dbRow.application_or_system,
            applicationOtherText: dbRow.application_other_text || '',
            environment: dbRow.environment,
            requestType: dbRow.request_type,
            requestedRoleOrPermission: dbRow.requested_role_or_permission,
            justification: dbRow.justification,
            urgency: dbRow.urgency,
            status: dbRow.status,
            iamAssigneeUserId: dbRow.iam_assignee_id,
            iamAssigneeName: dbRow.iam_assignee_name,
            statusHistory: [] // Will be populated from events
        };
    }

    function mapRequestToDb(request) {
        return {
            requester_id: request.requesterUserId,
            requester_name: request.requesterName,
            requester_email: request.requesterEmail,
            department: request.department,
            application_or_system: request.applicationOrSystem,
            application_other_text: request.applicationOtherText || null,
            environment: request.environment,
            request_type: request.requestType,
            requested_role_or_permission: request.requestedRoleOrPermission,
            justification: request.justification,
            urgency: request.urgency,
            status: request.status,
            iam_assignee_id: request.iamAssigneeUserId || null,
            iam_assignee_name: request.iamAssigneeName || null
        };
    }

    function mapEventFromDb(dbRow) {
        return {
            status: dbRow.new_value || dbRow.event_type,
            changedByUserId: dbRow.actor_id,
            changedByName: dbRow.actor_name,
            changedAt: dbRow.created_at,
            note: dbRow.comment || formatEventNote(dbRow),
            eventType: dbRow.event_type,
            oldValue: dbRow.old_value,
            newValue: dbRow.new_value
        };
    }

    function formatEventNote(event) {
        switch (event.event_type) {
            case 'created': return 'Request submitted';
            case 'status_changed': return `Status changed from ${event.old_value} to ${event.new_value}`;
            case 'assigned': return `Assigned to ${event.new_value || 'Unassigned'}`;
            case 'comment_added': return event.comment;
            case 'comment_employee': return event.comment;
            default: return event.event_type;
        }
    }

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
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
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
        const createdAt = new Date(request.createdAt);
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
    function showModal(content) {
        const overlay = document.getElementById('modal-overlay');
        const container = document.getElementById('modal-container');
        container.innerHTML = content;
        overlay.classList.remove('hidden');
    }

    function closeModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }

    // ===== Permission Checks =====
    function canViewAllRequests() {
        return state.currentUser && (state.currentUser.isIam || state.currentUser.isAdmin);
    }

    function canManageUsers() {
        return state.currentUser && state.currentUser.isAdmin;
    }

    // ===== Data Loading =====
    async function loadRequests() {
        try {
            const dbRequests = await supabaseGetRequests();
            state.requests = dbRequests.map(mapRequestFromDb);
            return state.requests;
        } catch (error) {
            console.error('Failed to load requests:', error);
            showToast('Failed to load requests', 'error');
            return [];
        }
    }

    async function loadRequestEvents(dbId) {
        try {
            const events = await supabaseGetRequestEvents(dbId);
            return events.map(mapEventFromDb);
        } catch (error) {
            console.error('Failed to load events:', error);
            return [];
        }
    }

    // ===== Login =====
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

    // ===== Header & Navigation =====
    function updateHeader() {
        document.getElementById('user-identity').textContent = state.currentUser.name;

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
        document.getElementById('role-badges').innerHTML = badges;
    }

    function renderNav() {
        const nav = document.getElementById('app-nav');
        let navItems = `
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
        state.filters = { status: '', urgency: '', search: '' };

        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.view === view);
        });

        const main = document.getElementById('app-main');

        switch (view) {
            case 'new-request':
                renderNewRequestForm(main);
                break;
            case 'my-requests':
                renderMyRequests(main);
                break;
            case 'dashboard':
                if (canViewAllRequests()) {
                    renderDashboard(main);
                } else {
                    navigateTo('my-requests');
                }
                break;
            default:
                navigateTo('new-request');
        }
    }

    // ===== Request Form (ORIGINAL UI PRESERVED) =====
    function renderNewRequestForm(container) {
        const systemOptions = SYSTEMS.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
        const envOptions = ENVIRONMENTS.map(e => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`).join('');
        const typeOptions = REQUEST_TYPES.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
        const urgencyOptions = URGENCIES.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('');

        container.innerHTML = `
            <div class="request-form-container">
                <div class="card">
                    <div class="card-header">
                        <h2>New Access Request</h2>
                    </div>
                    <div class="card-body">
                        <form id="new-request-form">
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Your Name</label>
                                    <input type="text" class="form-control" value="${escapeHtml(state.currentUser.name)}" readonly>
                                </div>
                                <div class="form-group">
                                    <label>Your Email</label>
                                    <input type="text" class="form-control" value="${escapeHtml(state.currentUser.email)}" readonly>
                                </div>
                            </div>

                            <div class="form-group">
                                <label>Department / Team <span class="required">*</span></label>
                                <input type="text" class="form-control" id="req-department" value="${escapeHtml(state.currentUser.defaultDepartment || '')}" placeholder="e.g., Engineering, Finance, HR" required>
                            </div>

                            <div class="form-row">
                                <div class="form-group">
                                    <label>Application / System <span class="required">*</span></label>
                                    <select class="form-control" id="req-system" required>
                                        <option value="">-- Select --</option>
                                        ${systemOptions}
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Environment <span class="required">*</span></label>
                                    <select class="form-control" id="req-environment" required>
                                        <option value="">-- Select --</option>
                                        ${envOptions}
                                    </select>
                                </div>
                            </div>

                            <div class="form-group hidden" id="other-system-group">
                                <label>Specify Other System <span class="required">*</span></label>
                                <input type="text" class="form-control" id="req-other-system" placeholder="Enter the system name">
                            </div>

                            <div class="form-row">
                                <div class="form-group">
                                    <label>Request Type <span class="required">*</span></label>
                                    <select class="form-control" id="req-type" required>
                                        <option value="">-- Select --</option>
                                        ${typeOptions}
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Urgency <span class="required">*</span></label>
                                    <select class="form-control" id="req-urgency" required>
                                        <option value="">-- Select --</option>
                                        ${urgencyOptions}
                                    </select>
                                </div>
                            </div>

                            <div class="form-group">
                                <label>Requested Role / Permission <span class="required">*</span></label>
                                <input type="text" class="form-control" id="req-role" placeholder="e.g., Read-only access, Admin role, Viewer" required>
                            </div>

                            <div class="form-group">
                                <label>Business Justification <span class="required">*</span></label>
                                <textarea class="form-control" id="req-justification" placeholder="Explain why you need this access..." required></textarea>
                            </div>
                        </form>
                    </div>
                    <div class="card-footer">
                        <button type="button" class="btn btn-secondary" id="clear-form-btn">Clear</button>
                        <button type="button" class="btn btn-primary" id="submit-request-btn">Submit Request</button>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('req-system').addEventListener('change', (e) => {
            const otherGroup = document.getElementById('other-system-group');
            const otherInput = document.getElementById('req-other-system');
            if (e.target.value === 'Other') {
                otherGroup.classList.remove('hidden');
                otherInput.required = true;
            } else {
                otherGroup.classList.add('hidden');
                otherInput.required = false;
            }
        });

        document.getElementById('clear-form-btn').addEventListener('click', () => {
            document.getElementById('new-request-form').reset();
            document.getElementById('other-system-group').classList.add('hidden');
        });

        document.getElementById('submit-request-btn').addEventListener('click', submitNewRequest);
    }

    async function submitNewRequest() {
        const form = document.getElementById('new-request-form');
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
            requesterUserId: state.currentUser.userId,
            requesterName: state.currentUser.name,
            requesterEmail: state.currentUser.email,
            department: document.getElementById('req-department').value.trim(),
            applicationOrSystem: system,
            applicationOtherText: system === 'Other' ? otherSystem : '',
            environment: document.getElementById('req-environment').value,
            requestType: document.getElementById('req-type').value,
            requestedRoleOrPermission: document.getElementById('req-role').value.trim(),
            justification: document.getElementById('req-justification').value.trim(),
            urgency: document.getElementById('req-urgency').value,
            status: 'New'
        };

        try {
            const dbData = mapRequestToDb(request);
            const created = await supabaseCreateRequest(dbData);

            // Add creation event
            await supabaseAddRequestEvent({
                request_id: created.id,
                actor_id: state.currentUser.userId,
                actor_name: state.currentUser.name,
                actor_email: state.currentUser.email,
                event_type: 'created',
                new_value: 'New',
                comment: 'Request submitted'
            });

            await loadRequests();
            showToast('Request submitted successfully!', 'success');
            navigateTo('my-requests');
        } catch (error) {
            console.error('Failed to submit request:', error);
            showToast('Failed to submit request', 'error');
        }
    }

    // ===== My Requests (ORIGINAL UI PRESERVED) =====
    function renderMyRequests(container) {
        const myRequests = state.requests
            .filter(r => r.requesterUserId === state.currentUser.userId)
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

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

        document.getElementById('my-search').addEventListener('input', (e) => {
            state.filters.search = e.target.value.toLowerCase();
            renderMyRequestsList(myRequests);
        });

        document.getElementById('my-status-filter').addEventListener('change', (e) => {
            state.filters.status = e.target.value;
            renderMyRequestsList(myRequests);
        });

        renderMyRequestsList(myRequests);
    }

    function renderMyRequestsList(requests) {
        const filtered = requests.filter(r => {
            if (state.filters.status && r.status !== state.filters.status) return false;
            if (state.filters.search) {
                const searchStr = `${r.id} ${r.applicationOrSystem} ${r.requestType} ${r.status}`.toLowerCase();
                if (!searchStr.includes(state.filters.search)) return false;
            }
            return true;
        });

        const listContainer = document.getElementById('my-requests-list');

        if (filtered.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">&#128196;</div>
                    <h3>No requests found</h3>
                    <p>Submit a new request to get started</p>
                </div>
            `;
            return;
        }

        listContainer.innerHTML = `
            <table class="request-table">
                <thead>
                    <tr>
                        <th>Request ID</th>
                        <th>System</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Urgency</th>
                        <th>Updated</th>
                    </tr>
                </thead>
                <tbody>
                    ${filtered.map(r => `
                        <tr data-id="${escapeHtml(r.id)}">
                            <td><span class="request-id">${escapeHtml(r.id)}</span></td>
                            <td>${escapeHtml(r.applicationOrSystem === 'Other' ? r.applicationOtherText : r.applicationOrSystem)}</td>
                            <td>${escapeHtml(r.requestType)}</td>
                            <td><span class="status-badge ${getStatusClass(r.status)}">${escapeHtml(r.status)}</span></td>
                            <td><span class="urgency-badge ${r.urgency.toLowerCase()}">${escapeHtml(r.urgency)}</span></td>
                            <td>${formatDateShort(r.updatedAt)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        listContainer.querySelectorAll('tbody tr').forEach(row => {
            row.addEventListener('click', () => {
                const request = state.requests.find(r => r.id === row.dataset.id);
                if (request) showRequestDetail(request);
            });
        });
    }

    // ===== Dashboard (ORIGINAL UI PRESERVED) =====
    function renderDashboard(container) {
        if (!canViewAllRequests()) {
            navigateTo('my-requests');
            return;
        }

        const requests = state.requests.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

        const stats = {
            total: requests.length,
            new: requests.filter(r => r.status === 'New').length,
            inReview: requests.filter(r => r.status === 'In Review').length,
            needInfo: requests.filter(r => r.status === 'Need Info').length,
            overdue: requests.filter(r => isOverSLA(r)).length
        };

        const statusOptions = ['', ...STATUSES].map(s =>
            `<option value="${escapeHtml(s)}">${s || 'All Statuses'}</option>`
        ).join('');

        const urgencyOptions = ['', ...URGENCIES].map(u =>
            `<option value="${escapeHtml(u)}">${u || 'All Urgencies'}</option>`
        ).join('');

        container.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card highlight">
                    <div class="stat-value">${stats.new}</div>
                    <div class="stat-label">New Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.inReview}</div>
                    <div class="stat-label">In Review</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.needInfo}</div>
                    <div class="stat-label">Need Info</div>
                </div>
                <div class="stat-card" style="${stats.overdue > 0 ? 'border-color: var(--danger-color);' : ''}">
                    <div class="stat-value" style="${stats.overdue > 0 ? 'color: var(--danger-color);' : ''}">${stats.overdue}</div>
                    <div class="stat-label">Over SLA (>7 days)</div>
                </div>
            </div>

            <div class="list-header">
                <h2 class="list-title">All Requests</h2>
                <div class="list-filters">
                    <input type="text" class="form-control search-input" id="iam-search" placeholder="Search...">
                    <select class="form-control" id="iam-status-filter">${statusOptions}</select>
                    <select class="form-control" id="iam-urgency-filter">${urgencyOptions}</select>
                </div>
            </div>
            <div class="card">
                <div class="card-body" style="padding: 0;">
                    <div id="iam-requests-list"></div>
                </div>
            </div>
        `;

        document.getElementById('iam-search').addEventListener('input', (e) => {
            state.filters.search = e.target.value.toLowerCase();
            renderIAMRequestsList(requests);
        });

        document.getElementById('iam-status-filter').addEventListener('change', (e) => {
            state.filters.status = e.target.value;
            renderIAMRequestsList(requests);
        });

        document.getElementById('iam-urgency-filter').addEventListener('change', (e) => {
            state.filters.urgency = e.target.value;
            renderIAMRequestsList(requests);
        });

        renderIAMRequestsList(requests);
    }

    function renderIAMRequestsList(requests) {
        const filtered = requests.filter(r => {
            if (state.filters.status && r.status !== state.filters.status) return false;
            if (state.filters.urgency && r.urgency !== state.filters.urgency) return false;
            if (state.filters.search) {
                const searchStr = `${r.id} ${r.requesterName} ${r.requesterEmail} ${r.applicationOrSystem} ${r.department}`.toLowerCase();
                if (!searchStr.includes(state.filters.search)) return false;
            }
            return true;
        });

        const listContainer = document.getElementById('iam-requests-list');

        if (filtered.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">&#128269;</div>
                    <h3>No requests found</h3>
                    <p>Try adjusting your filters</p>
                </div>
            `;
            return;
        }

        listContainer.innerHTML = `
            <table class="request-table">
                <thead>
                    <tr>
                        <th>Request ID</th>
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
                        <tr data-id="${escapeHtml(r.id)}">
                            <td><span class="request-id">${escapeHtml(r.id)}</span></td>
                            <td>${escapeHtml(r.requesterName)}</td>
                            <td>${escapeHtml(r.applicationOrSystem === 'Other' ? r.applicationOtherText : r.applicationOrSystem)}</td>
                            <td>${escapeHtml(r.requestType)}</td>
                            <td><span class="status-badge ${getStatusClass(r.status)}">${escapeHtml(r.status)}</span></td>
                            <td><span class="urgency-badge ${r.urgency.toLowerCase()}">${escapeHtml(r.urgency)}</span></td>
                            <td>${isOverSLA(r) ? '<span class="sla-warning">⚠</span>' : '-'}</td>
                            <td>${formatDateShort(r.updatedAt)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        listContainer.querySelectorAll('tbody tr').forEach(row => {
            row.addEventListener('click', () => {
                const request = state.requests.find(r => r.id === row.dataset.id);
                if (request) showRequestDetail(request);
            });
        });
    }

    // ===== Request Detail Modal =====
    async function showRequestDetail(request) {
        const events = await loadRequestEvents(request.dbId);
        const isOwner = request.requesterUserId === state.currentUser.userId;
        const canEdit = canViewAllRequests();
        const canComment = canEdit || (isOwner && request.status === 'Need Info');

        const statusOptions = STATUSES.map(s =>
            `<option value="${escapeHtml(s)}" ${request.status === s ? 'selected' : ''}>${escapeHtml(s)}</option>`
        ).join('');

        const content = `
            <div class="modal-header">
                <h2>${escapeHtml(request.id)}</h2>
                <button class="modal-close" id="close-modal-btn">&times;</button>
            </div>
            <div class="modal-body">
                <div class="detail-grid">
                    <div class="detail-section">
                        <h3>Request Details</h3>
                        <div class="detail-item">
                            <span class="detail-label">Requester</span>
                            <span class="detail-value">${escapeHtml(request.requesterName)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Email</span>
                            <span class="detail-value">${escapeHtml(request.requesterEmail)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Department</span>
                            <span class="detail-value">${escapeHtml(request.department)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">System</span>
                            <span class="detail-value">${escapeHtml(request.applicationOrSystem === 'Other' ? request.applicationOtherText : request.applicationOrSystem)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Environment</span>
                            <span class="detail-value">${escapeHtml(request.environment)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Request Type</span>
                            <span class="detail-value">${escapeHtml(request.requestType)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Requested Role/Permission</span>
                            <span class="detail-value">${escapeHtml(request.requestedRoleOrPermission)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Justification</span>
                            <span class="detail-value">${escapeHtml(request.justification)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Urgency</span>
                            <span class="detail-value"><span class="urgency-badge ${request.urgency.toLowerCase()}">${escapeHtml(request.urgency)}</span></span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created</span>
                            <span class="detail-value">${formatDate(request.createdAt)}</span>
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
                                       value="${escapeHtml(request.iamAssigneeName || '')}"
                                       placeholder="Enter assignee name">
                            </div>
                        ` : `
                            <div class="detail-item">
                                <span class="detail-label">Status</span>
                                <span class="detail-value"><span class="status-badge ${getStatusClass(request.status)}">${escapeHtml(request.status)}</span></span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Assignee</span>
                                <span class="detail-value">${escapeHtml(request.iamAssigneeName || 'Unassigned')}</span>
                            </div>
                        `}

                        <h3 style="margin-top: 24px;">Activity History</h3>
                        <div class="activity-list">
                            ${events.length === 0 ? '<p class="text-muted">No activity yet</p>' :
                              events.map(event => `
                                <div class="activity-item">
                                    <div class="activity-header">
                                        <strong>${escapeHtml(event.changedByName)}</strong>
                                        <span class="activity-time">${formatDate(event.changedAt)}</span>
                                    </div>
                                    <div class="activity-content">${escapeHtml(event.note)}</div>
                                </div>
                              `).join('')}
                        </div>

                        ${canComment ? `
                            <h3 style="margin-top: 24px;">Add Comment</h3>
                            <div class="form-group">
                                <textarea class="form-control" id="detail-comment" placeholder="Enter your comment..."></textarea>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" id="close-modal-btn-footer">Close</button>
                ${canEdit || canComment ? `<button class="btn btn-primary" id="save-detail-btn">Save Changes</button>` : ''}
            </div>
        `;

        showModal(content);

        document.getElementById('close-modal-btn').addEventListener('click', closeModal);
        document.getElementById('close-modal-btn-footer').addEventListener('click', closeModal);

        const saveBtn = document.getElementById('save-detail-btn');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => saveRequestChanges(request));
        }

        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'modal-overlay') closeModal();
        });
    }

    async function saveRequestChanges(request) {
        const canEdit = canViewAllRequests();
        const updates = {};
        const eventsToAdd = [];

        if (canEdit) {
            const newStatus = document.getElementById('detail-status')?.value;
            const newAssignee = document.getElementById('detail-assignee')?.value.trim();

            if (newStatus && newStatus !== request.status) {
                updates.status = newStatus;
                eventsToAdd.push({
                    request_id: request.dbId,
                    actor_id: state.currentUser.userId,
                    actor_name: state.currentUser.name,
                    actor_email: state.currentUser.email,
                    event_type: 'status_changed',
                    old_value: request.status,
                    new_value: newStatus
                });
            }

            if (newAssignee !== (request.iamAssigneeName || '')) {
                updates.iam_assignee_name = newAssignee || null;
                updates.iam_assignee_id = newAssignee ? state.currentUser.userId : null;
                eventsToAdd.push({
                    request_id: request.dbId,
                    actor_id: state.currentUser.userId,
                    actor_name: state.currentUser.name,
                    actor_email: state.currentUser.email,
                    event_type: 'assigned',
                    old_value: request.iamAssigneeName,
                    new_value: newAssignee || null
                });
            }
        }

        const comment = document.getElementById('detail-comment')?.value.trim();
        if (comment) {
            eventsToAdd.push({
                request_id: request.dbId,
                actor_id: state.currentUser.userId,
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
                await supabaseUpdateRequest(request.dbId, updates);
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

            const main = document.getElementById('app-main');
            if (state.currentView === 'dashboard' && canViewAllRequests()) {
                renderDashboard(main);
            } else if (state.currentView === 'my-requests') {
                renderMyRequests(main);
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
        console.log('TRIARQ IAM Portal v3.2 - Original UI with Supabase Backend');

        const savedUser = loadSession();
        if (savedUser && DEMO_USERS[savedUser.userId]) {
            state.currentUser = DEMO_USERS[savedUser.userId];
            await initMainApp();
        } else {
            showScreen('login-screen');
        }

        initLoginForm();
        document.getElementById('logout-btn').addEventListener('click', handleSignOut);
    }

    document.addEventListener('DOMContentLoaded', init);

})();
