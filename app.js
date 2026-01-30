// ===== TRIARQ IAM Access Request Portal v2.0 =====
// With User Authentication, Audit Logging, and Role-Based Access Control

(function() {
    'use strict';

    // ===== Constants =====
    const DB_NAME = 'TriarqIAMPortal';
    const DB_VERSION = 2; // Upgraded from v1
    const STORES = {
        USERS: 'users',
        REQUESTS: 'requests',
        AUDIT: 'audit',
        SETTINGS: 'settings'
    };
    const EMAIL_DOMAIN = '@TRIARQHealth.com';
    const SLA_DAYS = 7;
    const DEMO_PASSWORD = 'DemoPass123!';
    const MIN_PASSWORD_LENGTH = 8;
    const MAX_FAILED_ATTEMPTS = 5;
    const LOCKOUT_MINUTES = 5;

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

    const AUDIT_ACTIONS = {
        LOGIN_SUCCESS: 'LOGIN_SUCCESS',
        LOGIN_FAILURE: 'LOGIN_FAILURE',
        LOGOUT: 'LOGOUT',
        USER_CREATE: 'USER_CREATE',
        USER_UPDATE: 'USER_UPDATE',
        USER_DEACTIVATE: 'USER_DEACTIVATE',
        USER_REACTIVATE: 'USER_REACTIVATE',
        PASSWORD_RESET: 'PASSWORD_RESET',
        REQUEST_CREATE: 'REQUEST_CREATE',
        REQUEST_STATUS_CHANGE: 'REQUEST_STATUS_CHANGE',
        REQUEST_ASSIGN: 'REQUEST_ASSIGN',
        COMMENT_ADD: 'COMMENT_ADD'
    };

    // ===== State =====
    let db = null;
    let broadcastChannel = null;
    let state = {
        currentUser: null,
        users: [],
        requests: [],
        auditLogs: [],
        currentView: null,
        filters: {
            status: '',
            urgency: '',
            search: '',
            auditAction: '',
            auditUser: '',
            auditSuccess: ''
        }
    };

    // ===== Crypto Functions =====
    // Check if Web Crypto API is available (not available on file:// in some browsers)
    const cryptoAvailable = window.crypto && window.crypto.subtle;

    async function generateSalt() {
        if (cryptoAvailable) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            return Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            // Fallback: simple random string (less secure, demo only)
            return Math.random().toString(36).substring(2) + Date.now().toString(36);
        }
    }

    async function hashPassword(password, salt) {
        if (cryptoAvailable) {
            try {
                const encoder = new TextEncoder();
                const passwordData = encoder.encode(password);
                const saltData = encoder.encode(salt);

                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    passwordData,
                    'PBKDF2',
                    false,
                    ['deriveBits']
                );

                const derivedBits = await crypto.subtle.deriveBits(
                    {
                        name: 'PBKDF2',
                        salt: saltData,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    256
                );

                const hashArray = Array.from(new Uint8Array(derivedBits));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            } catch (e) {
                console.warn('Web Crypto failed, using fallback:', e);
                return fallbackHash(password, salt);
            }
        } else {
            // Fallback: simple hash (NOT secure, demo only)
            console.warn('Web Crypto not available, using fallback hash');
            return fallbackHash(password, salt);
        }
    }

    function fallbackHash(password, salt) {
        // Simple hash for demo purposes when crypto.subtle unavailable
        let hash = 0;
        const str = salt + password + salt;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return 'fallback_' + Math.abs(hash).toString(16) + '_' + btoa(salt + password).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
    }

    async function verifyPassword(password, salt, storedHash) {
        const hash = await hashPassword(password, salt);
        return hash === storedHash;
    }

    // ===== IndexedDB Functions =====
    function openDatabase() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error('IndexedDB is not supported'));
                return;
            }

            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onerror = (event) => {
                console.error('IndexedDB open error:', event.target.error);
                reject(event.target.error);
            };

            request.onsuccess = (event) => {
                db = event.target.result;
                console.log('IndexedDB opened successfully, version:', db.version);
                db.onerror = (event) => console.error('IndexedDB error:', event.target.error);
                resolve(db);
            };

            request.onupgradeneeded = (event) => {
                console.log('IndexedDB upgrade needed from version', event.oldVersion);
                const database = event.target.result;

                // Create users store
                if (!database.objectStoreNames.contains(STORES.USERS)) {
                    const userStore = database.createObjectStore(STORES.USERS, { keyPath: 'userId' });
                    userStore.createIndex('email', 'email', { unique: true });
                    console.log('Created users store');
                }

                // Create/upgrade requests store
                if (!database.objectStoreNames.contains(STORES.REQUESTS)) {
                    const requestStore = database.createObjectStore(STORES.REQUESTS, { keyPath: 'id' });
                    requestStore.createIndex('requesterUserId', 'requesterUserId', { unique: false });
                    requestStore.createIndex('status', 'status', { unique: false });
                    requestStore.createIndex('updatedAt', 'updatedAt', { unique: false });
                    console.log('Created requests store');
                }

                // Create audit store
                if (!database.objectStoreNames.contains(STORES.AUDIT)) {
                    const auditStore = database.createObjectStore(STORES.AUDIT, { keyPath: 'auditId', autoIncrement: true });
                    auditStore.createIndex('timestamp', 'timestamp', { unique: false });
                    auditStore.createIndex('actorUserId', 'actorUserId', { unique: false });
                    auditStore.createIndex('actionType', 'actionType', { unique: false });
                    console.log('Created audit store');
                }

                // Create settings store
                if (!database.objectStoreNames.contains(STORES.SETTINGS)) {
                    database.createObjectStore(STORES.SETTINGS, { keyPath: 'key' });
                    console.log('Created settings store');
                }
            };

            request.onblocked = () => {
                console.warn('IndexedDB blocked - please close other tabs');
            };
        });
    }

    // Generic DB operations
    function dbGet(storeName, key) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.get(key);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    function dbGetAll(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result || []);
            request.onerror = () => reject(request.error);
        });
    }

    function dbPut(storeName, data) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.put(data);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    function dbDelete(storeName, key) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.delete(key);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    function dbClear(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    function dbGetByIndex(storeName, indexName, value) {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const index = store.index(indexName);
            const request = index.get(value);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    // ===== Audit Logging =====
    async function logAudit(actionType, targetType, targetId, success, detail = {}) {
        const auditEntry = {
            timestamp: new Date().toISOString(),
            actorUserId: state.currentUser?.userId || null,
            actorName: state.currentUser?.name || 'System',
            actorEmail: state.currentUser?.email || null,
            actionType,
            targetType,
            targetId,
            success,
            detail: JSON.stringify(detail)
        };

        try {
            await dbPut(STORES.AUDIT, auditEntry);
            console.log('Audit logged:', actionType, success ? 'SUCCESS' : 'FAILURE');
        } catch (error) {
            console.error('Failed to log audit:', error);
        }
    }

    // ===== User Management =====
    async function createUser(userData) {
        const salt = await generateSalt();
        const passwordHash = await hashPassword(userData.password, salt);

        const user = {
            userId: 'USR-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
            name: userData.name,
            email: userData.email,
            defaultDepartment: userData.defaultDepartment || '',
            isIam: userData.isIam || false,
            isAdmin: userData.isAdmin || false,
            isActive: true,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            passwordSalt: salt,
            passwordHash: passwordHash,
            passwordParams: { iterations: 100000, hash: 'SHA-256' },
            failedLoginCount: 0,
            lockUntil: null
        };

        await dbPut(STORES.USERS, user);
        return user;
    }

    async function seedDefaultUsers() {
        try {
            const existingUsers = await dbGetAll(STORES.USERS);
            console.log('Existing users count:', existingUsers.length);

            if (existingUsers.length > 0) {
                console.log('Users already exist, skipping seed');
                return;
            }

            console.log('Seeding default users...');
            console.log('Crypto available:', cryptoAvailable);

            const defaultUsers = [
                { name: 'Jon', email: 'jon@TRIARQHealth.com', isIam: true, isAdmin: true, password: DEMO_PASSWORD },
                { name: 'Pintal', email: 'pintal@TRIARQHealth.com', isIam: true, isAdmin: false, password: DEMO_PASSWORD },
                { name: 'Ami', email: 'ami@TRIARQHealth.com', isIam: true, isAdmin: false, password: DEMO_PASSWORD },
                { name: 'Alice Johnson', email: 'alice.johnson@TRIARQHealth.com', isIam: false, isAdmin: false, password: DEMO_PASSWORD },
                { name: 'Bob Smith', email: 'bob.smith@TRIARQHealth.com', isIam: false, isAdmin: false, password: DEMO_PASSWORD }
            ];

            for (const userData of defaultUsers) {
                try {
                    await createUser(userData);
                    console.log('Created user:', userData.name);
                } catch (userError) {
                    console.error('Failed to create user:', userData.name, userError);
                }
            }

            await logAudit(AUDIT_ACTIONS.USER_CREATE, 'SYSTEM', 'SEED', true, { message: 'Seeded default users' });
            console.log('User seeding complete');
        } catch (error) {
            console.error('seedDefaultUsers error:', error);
        }
    }

    async function loadUsers() {
        state.users = await dbGetAll(STORES.USERS);
        console.log('Loaded', state.users.length, 'users');
    }

    // ===== Session Management =====
    function saveSession(user) {
        const session = {
            userId: user.userId,
            name: user.name,
            email: user.email,
            defaultDepartment: user.defaultDepartment || '',
            isIam: user.isIam,
            isAdmin: user.isAdmin,
            loginAt: new Date().toISOString()
        };
        localStorage.setItem('triarq_session', JSON.stringify(session));
    }

    function loadSession() {
        const sessionData = localStorage.getItem('triarq_session');
        if (sessionData) {
            try {
                return JSON.parse(sessionData);
            } catch (e) {
                return null;
            }
        }
        return null;
    }

    function clearSession() {
        localStorage.removeItem('triarq_session');
    }

    async function validateSession() {
        const session = loadSession();
        if (!session) return null;

        // Verify user still exists and is active
        const user = await dbGet(STORES.USERS, session.userId);
        if (user && user.isActive) {
            state.currentUser = {
                userId: user.userId,
                name: user.name,
                email: user.email,
                defaultDepartment: user.defaultDepartment || '',
                isIam: user.isIam,
                isAdmin: user.isAdmin
            };
            return state.currentUser;
        }

        clearSession();
        return null;
    }

    // ===== Authentication =====
    async function attemptLogin(email) {
        const user = await dbGetByIndex(STORES.USERS, 'email', email);

        if (!user) {
            await logAudit(AUDIT_ACTIONS.LOGIN_FAILURE, 'USER', email, false, { reason: 'User not found' });
            return { success: false, error: 'User not found' };
        }

        if (!user.isActive) {
            await logAudit(AUDIT_ACTIONS.LOGIN_FAILURE, 'USER', user.userId, false, { reason: 'Account inactive' });
            return { success: false, error: 'Account is deactivated' };
        }

        // Successful login (no password required for demo)
        state.currentUser = {
            userId: user.userId,
            name: user.name,
            email: user.email,
            defaultDepartment: user.defaultDepartment || '',
            isIam: user.isIam,
            isAdmin: user.isAdmin
        };

        saveSession(user);
        await logAudit(AUDIT_ACTIONS.LOGIN_SUCCESS, 'USER', user.userId, true, {});

        return { success: true, user: state.currentUser };
    }

    async function logout() {
        if (state.currentUser) {
            await logAudit(AUDIT_ACTIONS.LOGOUT, 'USER', state.currentUser.userId, true, {});
        }
        state.currentUser = null;
        clearSession();
        showLoginScreen();
    }

    // ===== BroadcastChannel for Cross-Tab Sync =====
    function initBroadcastChannel() {
        if ('BroadcastChannel' in window) {
            broadcastChannel = new BroadcastChannel('triarq_iam_sync');
            broadcastChannel.onmessage = async (event) => {
                const { type } = event.data;
                console.log('Received broadcast:', type);

                if (type === 'DATA_CHANGED') {
                    await loadAllData();
                    if (state.currentView) {
                        navigateTo(state.currentView);
                    }
                    showToast('Data updated from another tab', 'info');
                } else if (type === 'LOGOUT') {
                    state.currentUser = null;
                    clearSession();
                    showLoginScreen();
                }
            };
        }
    }

    function broadcastDataChange() {
        if (broadcastChannel) {
            broadcastChannel.postMessage({ type: 'DATA_CHANGED' });
        }
    }

    function broadcastLogout() {
        if (broadcastChannel) {
            broadcastChannel.postMessage({ type: 'LOGOUT' });
        }
    }

    // ===== Data Loading =====
    async function loadAllData() {
        state.users = await dbGetAll(STORES.USERS);
        state.requests = await dbGetAll(STORES.REQUESTS);
        state.auditLogs = await dbGetAll(STORES.AUDIT);
        console.log('Loaded data - Users:', state.users.length, 'Requests:', state.requests.length, 'Audit:', state.auditLogs.length);
    }

    // ===== Utility Functions =====
    function generateRequestId() {
        const num = Math.floor(Math.random() * 999999) + 1;
        return `REQ-${String(num).padStart(6, '0')}`;
    }

    function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    function formatDateShort(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    }

    function getDaysSinceCreation(createdAt) {
        const created = new Date(createdAt);
        const now = new Date();
        return Math.ceil(Math.abs(now - created) / (1000 * 60 * 60 * 24));
    }

    function isOverSLA(request) {
        if (request.status === 'Completed' || request.status === 'Declined') return false;
        return getDaysSinceCreation(request.createdAt) > SLA_DAYS;
    }

    function getStatusClass(status) {
        return status.toLowerCase().replace(/\s+/g, '-');
    }

    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    // ===== Permission Checks =====
    function canViewAllRequests() {
        return state.currentUser?.isIam || state.currentUser?.isAdmin;
    }

    function canChangeRequestStatus() {
        return state.currentUser?.isIam || state.currentUser?.isAdmin;
    }

    function canManageUsers() {
        return state.currentUser?.isAdmin;
    }

    function canViewAuditLogs() {
        return state.currentUser?.isAdmin;
    }

    // ===== Screen Management =====
    function showScreen(screenId) {
        document.querySelectorAll('.screen').forEach(screen => screen.classList.add('hidden'));
        document.getElementById(screenId).classList.remove('hidden');
    }

    function showModal(content) {
        const overlay = document.getElementById('modal-overlay');
        const container = document.getElementById('modal-container');
        container.innerHTML = content;
        overlay.classList.remove('hidden');
    }

    function hideModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }

    window.hideModal = hideModal;

    // ===== Login Screen =====
    function showLoginScreen() {
        showScreen('login-screen');
        populateUserDropdown();
    }

    async function populateUserDropdown() {
        console.log('Populating user dropdown...');
        await loadUsers();
        console.log('Users loaded:', state.users.length);

        const select = document.getElementById('login-email');
        const activeUsers = state.users.filter(u => u.isActive);
        console.log('Active users:', activeUsers.length);

        select.innerHTML = '<option value="">-- Select User --</option>' +
            activeUsers.map(u => `<option value="${escapeHtml(u.email)}">${escapeHtml(u.name)} (${escapeHtml(u.email)})</option>`).join('');
    }

    function initLoginForm() {
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const errorDiv = document.getElementById('login-error');

            if (!email) {
                errorDiv.textContent = 'Please select a user';
                errorDiv.classList.remove('hidden');
                return;
            }

            const loginBtn = document.getElementById('login-btn');
            loginBtn.disabled = true;
            loginBtn.textContent = 'Signing in...';

            const result = await attemptLogin(email);

            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';

            if (result.success) {
                errorDiv.classList.add('hidden');
                await initMainApp();
            } else {
                errorDiv.textContent = result.error;
                errorDiv.classList.remove('hidden');
            }
        });

        // Reset database button on login screen
        document.getElementById('login-reset-db-btn').addEventListener('click', resetDatabase);
    }

    async function resetDatabase() {
        const password = prompt('Enter admin password to reset database:');

        if (password === null) {
            return; // User cancelled
        }

        if (password !== 'DemoPass123!') {
            showToast('Incorrect password', 'error');
            return;
        }

        if (!confirm('This will DELETE ALL DATA and reset to default users. Are you sure?')) {
            return;
        }

        try {
            if (db) {
                db.close();
            }

            await new Promise((resolve, reject) => {
                const request = indexedDB.deleteDatabase(DB_NAME);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
                request.onblocked = () => resolve();
            });

            clearSession();
            showToast('Database reset. Reloading...', 'success');

            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } catch (error) {
            console.error('Failed to reset database:', error);
            showToast('Failed to reset database', 'error');
        }
    }

    // ===== Main Application =====
    async function initMainApp() {
        showScreen('main-app');
        updateHeader();
        renderNav();
        await loadAllData();

        // Set default view based on role
        if (canViewAllRequests()) {
            navigateTo('dashboard');
        } else {
            navigateTo('new-request');
        }
    }

    function updateHeader() {
        const badgesContainer = document.getElementById('role-badges');
        const identity = document.getElementById('user-identity');

        let badges = '';
        if (!state.currentUser.isIam && !state.currentUser.isAdmin) {
            badges = '<span class="role-badge employee">Employee</span>';
        }
        if (state.currentUser.isIam) {
            badges += '<span class="role-badge iam">IAM</span>';
        }
        if (state.currentUser.isAdmin) {
            badges += '<span class="role-badge admin">Admin</span>';
        }

        badgesContainer.innerHTML = badges;
        identity.textContent = state.currentUser.name;
    }

    function renderNav() {
        const nav = document.getElementById('app-nav');
        let navItems = '';

        // Employee can create requests
        navItems += '<button class="nav-btn" data-view="new-request">New Request</button>';
        navItems += '<button class="nav-btn" data-view="my-requests">My Requests</button>';

        // IAM can see dashboard
        if (canViewAllRequests()) {
            navItems += '<button class="nav-btn" data-view="dashboard">All Requests</button>';
        }

        // Admin can manage users and view audit
        if (canManageUsers()) {
            navItems += '<button class="nav-btn" data-view="users">Users</button>';
        }
        if (canViewAuditLogs()) {
            navItems += '<button class="nav-btn" data-view="audit">Audit Log</button>';
        }

        nav.innerHTML = navItems;

        nav.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => navigateTo(btn.dataset.view));
        });
    }

    function navigateTo(view) {
        state.currentView = view;
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === view);
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
            case 'users':
                if (canManageUsers()) {
                    renderUserManagement(main);
                } else {
                    navigateTo('my-requests');
                }
                break;
            case 'audit':
                if (canViewAuditLogs()) {
                    renderAuditLog(main);
                } else {
                    navigateTo('my-requests');
                }
                break;
        }
    }

    // ===== Request Form =====
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

        const now = new Date().toISOString();

        const request = {
            id: generateRequestId(),
            createdAt: now,
            updatedAt: now,
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
            status: 'New',
            iamAssigneeUserId: null,
            iamAssigneeName: null,
            iamComments: [],
            employeeComments: [],
            statusHistory: [{
                status: 'New',
                changedByUserId: state.currentUser.userId,
                changedByName: state.currentUser.name,
                changedAt: now,
                note: 'Request submitted'
            }]
        };

        try {
            await dbPut(STORES.REQUESTS, request);
            state.requests.push(request);
            await logAudit(AUDIT_ACTIONS.REQUEST_CREATE, 'REQUEST', request.id, true, { system, requestType: request.requestType });
            broadcastDataChange();
            showToast('Request submitted successfully!', 'success');
            navigateTo('my-requests');
        } catch (error) {
            console.error('Failed to submit request:', error);
            showToast('Failed to submit request', 'error');
        }
    }

    // ===== My Requests =====
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

    // ===== Dashboard (IAM) =====
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

        const iamUsers = state.users.filter(u => u.isIam && u.isActive);

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
                        <th>Assignee</th>
                        <th>SLA</th>
                    </tr>
                </thead>
                <tbody>
                    ${filtered.map(r => {
                        const overdue = isOverSLA(r);
                        const days = getDaysSinceCreation(r.createdAt);
                        return `
                            <tr data-id="${escapeHtml(r.id)}">
                                <td><span class="request-id">${escapeHtml(r.id)}</span></td>
                                <td>${escapeHtml(r.requesterName)}</td>
                                <td>${escapeHtml(r.applicationOrSystem === 'Other' ? r.applicationOtherText : r.applicationOrSystem)}</td>
                                <td>${escapeHtml(r.requestType)}</td>
                                <td><span class="status-badge ${getStatusClass(r.status)}">${escapeHtml(r.status)}</span></td>
                                <td><span class="urgency-badge ${r.urgency.toLowerCase()}">${escapeHtml(r.urgency)}</span></td>
                                <td>${r.iamAssigneeName ? escapeHtml(r.iamAssigneeName) : '<em style="color: var(--text-muted);">Unassigned</em>'}</td>
                                <td><span class="sla-indicator ${overdue ? 'overdue' : ''}">${days} day${days !== 1 ? 's' : ''}</span></td>
                            </tr>
                        `;
                    }).join('')}
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
    function showRequestDetail(request) {
        const isIAM = canViewAllRequests();
        const isOwner = request.requesterUserId === state.currentUser.userId;
        const canComment = isIAM || (isOwner && request.status === 'Need Info');
        const systemDisplay = request.applicationOrSystem === 'Other' ? request.applicationOtherText : request.applicationOrSystem;

        const statusOptions = STATUSES.map(s =>
            `<option value="${escapeHtml(s)}" ${request.status === s ? 'selected' : ''}>${escapeHtml(s)}</option>`
        ).join('');

        const iamUsers = state.users.filter(u => u.isIam && u.isActive);
        const assigneeOptions = [{ userId: '', name: '-- Unassigned --' }, ...iamUsers].map(u =>
            `<option value="${escapeHtml(u.userId)}" ${request.iamAssigneeUserId === u.userId ? 'selected' : ''}>${escapeHtml(u.name)}</option>`
        ).join('');

        const allComments = [
            ...request.iamComments.map(c => ({ ...c, type: 'iam' })),
            ...request.employeeComments.map(c => ({ ...c, type: 'employee' }))
        ].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        showModal(`
            <div class="modal-header">
                <h2>Request ${escapeHtml(request.id)}</h2>
                <button class="modal-close" onclick="hideModal()">&times;</button>
            </div>
            <div class="modal-body">
                ${isIAM ? `
                    <div class="iam-actions">
                        <div class="form-group">
                            <label>Status</label>
                            <select class="form-control" id="detail-status" data-original="${escapeHtml(request.status)}">
                                ${statusOptions}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Assignee</label>
                            <select class="form-control" id="detail-assignee" data-original="${escapeHtml(request.iamAssigneeUserId || '')}">
                                ${assigneeOptions}
                            </select>
                        </div>
                        <div class="unsaved-indicator hidden" id="unsaved-indicator">
                            <span style="color: var(--warning-color); font-size: 13px;">* Unsaved changes</span>
                        </div>
                    </div>
                ` : ''}

                <div class="detail-section">
                    <h3 class="detail-section-title">Request Information</h3>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">Status</span>
                            <span class="detail-value"><span class="status-badge ${getStatusClass(request.status)}">${escapeHtml(request.status)}</span></span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Urgency</span>
                            <span class="detail-value"><span class="urgency-badge ${request.urgency.toLowerCase()}">${escapeHtml(request.urgency)}</span></span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created</span>
                            <span class="detail-value">${formatDate(request.createdAt)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Last Updated</span>
                            <span class="detail-value">${formatDate(request.updatedAt)}</span>
                        </div>
                    </div>
                </div>

                <div class="detail-section">
                    <h3 class="detail-section-title">Requester</h3>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">Name</span>
                            <span class="detail-value">${escapeHtml(request.requesterName)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Email</span>
                            <span class="detail-value">${escapeHtml(request.requesterEmail)}</span>
                        </div>
                        <div class="detail-item full-width">
                            <span class="detail-label">Department / Team</span>
                            <span class="detail-value">${escapeHtml(request.department)}</span>
                        </div>
                    </div>
                </div>

                <div class="detail-section">
                    <h3 class="detail-section-title">Access Details</h3>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">System</span>
                            <span class="detail-value">${escapeHtml(systemDisplay)}</span>
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
                        <div class="detail-item full-width">
                            <span class="detail-label">Business Justification</span>
                            <span class="detail-value">${escapeHtml(request.justification)}</span>
                        </div>
                    </div>
                </div>

                ${request.iamAssigneeName ? `
                    <div class="detail-section">
                        <h3 class="detail-section-title">Assignment</h3>
                        <div class="detail-item">
                            <span class="detail-label">IAM Assignee</span>
                            <span class="detail-value">${escapeHtml(request.iamAssigneeName)}</span>
                        </div>
                    </div>
                ` : ''}

                <div class="detail-section comments-section">
                    <h3 class="detail-section-title">Comments</h3>
                    <div class="comment-list" id="comment-list">
                        ${allComments.length === 0 ? '<p style="color: var(--text-muted); text-align: center;">No comments yet</p>' : ''}
                        ${allComments.map(c => `
                            <div class="comment-item ${c.type}-comment">
                                <div class="comment-header">
                                    <span class="comment-author">${escapeHtml(c.authorName)} ${c.type === 'iam' ? '(IAM)' : '(Employee)'}</span>
                                    <span class="comment-date">${formatDate(c.timestamp)}</span>
                                </div>
                                <div class="comment-text">${escapeHtml(c.text)}</div>
                            </div>
                        `).join('')}
                    </div>
                    ${canComment ? `
                        <div class="comment-form">
                            <textarea class="form-control" id="new-comment" placeholder="Add a comment..."></textarea>
                            <button class="btn btn-primary" id="add-comment-btn">Add</button>
                        </div>
                    ` : ''}
                    ${!canComment && isOwner ? `
                        <p style="color: var(--text-muted); font-size: 13px; margin-top: 8px;">You can only add comments when the request status is "Need Info"</p>
                    ` : ''}
                </div>

                <div class="detail-section">
                    <h3 class="detail-section-title">Status History</h3>
                    <div class="history-list">
                        ${request.statusHistory.map(h => `
                            <div class="history-item">
                                <div class="history-dot"></div>
                                <div class="history-content">
                                    <div class="history-text"><strong>${escapeHtml(h.status)}</strong> - ${escapeHtml(h.note || 'Status changed')} by ${escapeHtml(h.changedByName)}</div>
                                    <div class="history-date">${formatDate(h.changedAt)}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                ${isIAM ? `<button class="btn btn-success" id="save-changes-btn">Save Changes</button>` : ''}
                <button class="btn btn-secondary" onclick="hideModal()">Close</button>
            </div>
        `);

        // IAM change tracking and save
        if (isIAM) {
            const statusSelect = document.getElementById('detail-status');
            const assigneeSelect = document.getElementById('detail-assignee');
            const saveBtn = document.getElementById('save-changes-btn');
            const unsavedIndicator = document.getElementById('unsaved-indicator');

            function checkForChanges() {
                const hasChanges = statusSelect.value !== statusSelect.dataset.original ||
                                   assigneeSelect.value !== assigneeSelect.dataset.original;
                unsavedIndicator.classList.toggle('hidden', !hasChanges);
            }

            statusSelect.addEventListener('change', checkForChanges);
            assigneeSelect.addEventListener('change', checkForChanges);

            saveBtn.addEventListener('click', async () => {
                const newStatus = statusSelect.value;
                const newAssigneeUserId = assigneeSelect.value || null;
                const newAssignee = iamUsers.find(u => u.userId === newAssigneeUserId);

                const now = new Date().toISOString();
                let hasChanges = false;

                if (newStatus !== request.status) {
                    hasChanges = true;
                    request.statusHistory.push({
                        status: newStatus,
                        changedByUserId: state.currentUser.userId,
                        changedByName: state.currentUser.name,
                        changedAt: now,
                        note: `Status changed from ${request.status} to ${newStatus}`
                    });
                    await logAudit(AUDIT_ACTIONS.REQUEST_STATUS_CHANGE, 'REQUEST', request.id, true, {
                        oldStatus: request.status,
                        newStatus
                    });
                    request.status = newStatus;
                }

                if (newAssigneeUserId !== request.iamAssigneeUserId) {
                    hasChanges = true;
                    await logAudit(AUDIT_ACTIONS.REQUEST_ASSIGN, 'REQUEST', request.id, true, {
                        oldAssignee: request.iamAssigneeName,
                        newAssignee: newAssignee?.name || 'Unassigned'
                    });
                    request.iamAssigneeUserId = newAssigneeUserId;
                    request.iamAssigneeName = newAssignee?.name || null;
                }

                if (hasChanges) {
                    request.updatedAt = now;
                    try {
                        await dbPut(STORES.REQUESTS, request);
                        broadcastDataChange();
                        showToast('Request updated', 'success');
                        hideModal();
                        navigateTo('dashboard');
                    } catch (error) {
                        showToast('Failed to update request', 'error');
                    }
                } else {
                    showToast('No changes to save', 'info');
                }
            });
        }

        // Comment handler
        const addCommentBtn = document.getElementById('add-comment-btn');
        if (addCommentBtn) {
            addCommentBtn.addEventListener('click', async () => {
                const commentText = document.getElementById('new-comment').value.trim();
                if (!commentText) {
                    showToast('Please enter a comment', 'error');
                    return;
                }

                const comment = {
                    authorUserId: state.currentUser.userId,
                    authorName: state.currentUser.name,
                    text: commentText,
                    timestamp: new Date().toISOString()
                };

                if (isIAM) {
                    request.iamComments.push(comment);
                } else {
                    request.employeeComments.push(comment);
                }

                request.updatedAt = new Date().toISOString();

                try {
                    await dbPut(STORES.REQUESTS, request);
                    await logAudit(AUDIT_ACTIONS.COMMENT_ADD, 'REQUEST', request.id, true, { commentType: isIAM ? 'IAM' : 'Employee' });
                    broadcastDataChange();
                    showToast('Comment added', 'success');
                    showRequestDetail(request);
                } catch (error) {
                    showToast('Failed to add comment', 'error');
                }
            });
        }
    }

    // ===== User Management (Admin) =====
    function renderUserManagement(container) {
        if (!canManageUsers()) {
            navigateTo('my-requests');
            return;
        }

        container.innerHTML = `
            <div class="list-header">
                <h2 class="list-title">User Management</h2>
                <button class="btn btn-primary" id="add-user-btn">Add User</button>
            </div>
            <div class="card">
                <div class="card-body" style="padding: 0;">
                    <table class="user-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Department</th>
                                <th>Roles</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${state.users.map(u => {
                                const isLocked = u.lockUntil && new Date(u.lockUntil) > new Date();
                                let statusClass = u.isActive ? 'active' : 'inactive';
                                let statusText = u.isActive ? 'Active' : 'Inactive';
                                if (isLocked) {
                                    statusClass = 'locked';
                                    statusText = 'Locked';
                                }

                                const roles = [];
                                if (!u.isIam && !u.isAdmin) roles.push('Employee');
                                if (u.isIam) roles.push('IAM');
                                if (u.isAdmin) roles.push('Admin');

                                return `
                                    <tr>
                                        <td>${escapeHtml(u.name)}</td>
                                        <td>${escapeHtml(u.email)}</td>
                                        <td>${u.defaultDepartment ? escapeHtml(u.defaultDepartment) : '<em style="color: var(--text-muted);">—</em>'}</td>
                                        <td>${roles.map(r => `<span class="role-badge ${r.toLowerCase()}">${r}</span>`).join(' ')}</td>
                                        <td><span class="user-status ${statusClass}">${statusText}</span></td>
                                        <td>
                                            <button class="btn btn-sm btn-secondary edit-user-btn" data-userid="${escapeHtml(u.userId)}">Edit</button>
                                            <button class="btn btn-sm btn-secondary reset-pwd-btn" data-userid="${escapeHtml(u.userId)}">Reset Password</button>
                                        </td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        document.getElementById('add-user-btn').addEventListener('click', () => showUserModal());

        document.querySelectorAll('.edit-user-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const user = state.users.find(u => u.userId === btn.dataset.userid);
                if (user) showUserModal(user);
            });
        });

        document.querySelectorAll('.reset-pwd-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const user = state.users.find(u => u.userId === btn.dataset.userid);
                if (user) showResetPasswordModal(user);
            });
        });
    }

    function showUserModal(user = null) {
        const isEdit = !!user;
        const title = isEdit ? 'Edit User' : 'Add User';

        showModal(`
            <div class="modal-header">
                <h2>${title}</h2>
                <button class="modal-close" onclick="hideModal()">&times;</button>
            </div>
            <div class="modal-body">
                <form id="user-form">
                    <div class="form-group">
                        <label>Name <span class="required">*</span></label>
                        <input type="text" class="form-control" id="user-name" value="${escapeHtml(user?.name || '')}" required>
                    </div>
                    <div class="form-group">
                        <label>Email <span class="required">*</span></label>
                        <input type="email" class="form-control" id="user-email" value="${escapeHtml(user?.email || '')}" ${isEdit ? 'readonly' : 'required'}>
                    </div>
                    ${!isEdit ? `
                        <div class="form-group">
                            <label>Password <span class="required">*</span></label>
                            <input type="password" class="form-control" id="user-password" minlength="${MIN_PASSWORD_LENGTH}" required>
                            <small style="color: var(--text-muted);">Minimum ${MIN_PASSWORD_LENGTH} characters</small>
                        </div>
                    ` : ''}
                    <div class="form-group">
                        <label>Default Department / Team</label>
                        <input type="text" class="form-control" id="user-department" value="${escapeHtml(user?.defaultDepartment || '')}" placeholder="e.g., Engineering, Finance, HR (optional)">
                        <small style="color: var(--text-muted);">Will pre-fill on new access requests</small>
                    </div>
                    <div class="form-group">
                        <label>Roles</label>
                        <div class="checkbox-group">
                            <label class="checkbox-label">
                                <input type="checkbox" id="user-is-iam" ${user?.isIam ? 'checked' : ''}>
                                IAM Member
                            </label>
                            <label class="checkbox-label">
                                <input type="checkbox" id="user-is-admin" ${user?.isAdmin ? 'checked' : ''}>
                                Admin
                            </label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="user-is-active" ${user?.isActive !== false ? 'checked' : ''}>
                            Active
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
                <button type="button" class="btn btn-primary" id="save-user-btn">${isEdit ? 'Save Changes' : 'Create User'}</button>
            </div>
        `);

        document.getElementById('save-user-btn').addEventListener('click', async () => {
            const form = document.getElementById('user-form');
            if (!form.checkValidity()) {
                form.reportValidity();
                return;
            }

            const name = document.getElementById('user-name').value.trim();
            const email = document.getElementById('user-email').value.trim();
            const defaultDepartment = document.getElementById('user-department').value.trim();
            const isIam = document.getElementById('user-is-iam').checked;
            const isAdmin = document.getElementById('user-is-admin').checked;
            const isActive = document.getElementById('user-is-active').checked;

            try {
                if (isEdit) {
                    const wasActive = user.isActive;
                    user.name = name;
                    user.defaultDepartment = defaultDepartment;
                    user.isIam = isIam;
                    user.isAdmin = isAdmin;
                    user.isActive = isActive;
                    user.updatedAt = new Date().toISOString();

                    await dbPut(STORES.USERS, user);

                    if (wasActive && !isActive) {
                        await logAudit(AUDIT_ACTIONS.USER_DEACTIVATE, 'USER', user.userId, true, { name });
                    } else if (!wasActive && isActive) {
                        await logAudit(AUDIT_ACTIONS.USER_REACTIVATE, 'USER', user.userId, true, { name });
                    } else {
                        await logAudit(AUDIT_ACTIONS.USER_UPDATE, 'USER', user.userId, true, { name, isIam, isAdmin });
                    }

                    showToast('User updated', 'success');
                } else {
                    const password = document.getElementById('user-password').value;
                    const newUser = await createUser({ name, email, password, defaultDepartment, isIam, isAdmin });
                    await logAudit(AUDIT_ACTIONS.USER_CREATE, 'USER', newUser.userId, true, { name, email });
                    showToast('User created', 'success');
                }

                await loadUsers();
                broadcastDataChange();
                hideModal();
                renderUserManagement(document.getElementById('app-main'));
            } catch (error) {
                console.error('Failed to save user:', error);
                showToast('Failed to save user', 'error');
            }
        });
    }

    function showResetPasswordModal(user) {
        showModal(`
            <div class="modal-header">
                <h2>Reset Password</h2>
                <button class="modal-close" onclick="hideModal()">&times;</button>
            </div>
            <div class="modal-body">
                <p>Reset password for <strong>${escapeHtml(user.name)}</strong> (${escapeHtml(user.email)})?</p>
                <div class="form-group" style="margin-top: 16px;">
                    <label>New Password <span class="required">*</span></label>
                    <input type="password" class="form-control" id="new-password" minlength="${MIN_PASSWORD_LENGTH}" required>
                    <small style="color: var(--text-muted);">Minimum ${MIN_PASSWORD_LENGTH} characters</small>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
                <button type="button" class="btn btn-warning" id="reset-pwd-confirm-btn">Reset Password</button>
            </div>
        `);

        document.getElementById('reset-pwd-confirm-btn').addEventListener('click', async () => {
            const newPassword = document.getElementById('new-password').value;
            if (newPassword.length < MIN_PASSWORD_LENGTH) {
                showToast(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`, 'error');
                return;
            }

            try {
                const salt = await generateSalt();
                const hash = await hashPassword(newPassword, salt);

                user.passwordSalt = salt;
                user.passwordHash = hash;
                user.failedLoginCount = 0;
                user.lockUntil = null;
                user.updatedAt = new Date().toISOString();

                await dbPut(STORES.USERS, user);
                await logAudit(AUDIT_ACTIONS.PASSWORD_RESET, 'USER', user.userId, true, { resetBy: state.currentUser.name });

                showToast('Password reset successfully', 'success');
                hideModal();
            } catch (error) {
                console.error('Failed to reset password:', error);
                showToast('Failed to reset password', 'error');
            }
        });
    }

    // ===== Audit Log (Admin) =====
    function renderAuditLog(container) {
        if (!canViewAuditLogs()) {
            navigateTo('my-requests');
            return;
        }

        const auditLogs = state.auditLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        const actionOptions = ['', ...Object.values(AUDIT_ACTIONS)].map(a =>
            `<option value="${escapeHtml(a)}">${a || 'All Actions'}</option>`
        ).join('');

        const userOptions = ['', ...state.users.map(u => u.userId)].map(id => {
            const user = state.users.find(u => u.userId === id);
            return `<option value="${escapeHtml(id)}">${id ? escapeHtml(user?.name || id) : 'All Users'}</option>`;
        }).join('');

        container.innerHTML = `
            <div class="list-header">
                <h2 class="list-title">Audit Log</h2>
                <div class="list-filters">
                    <select class="form-control" id="audit-action-filter">${actionOptions}</select>
                    <select class="form-control" id="audit-user-filter">${userOptions}</select>
                    <select class="form-control" id="audit-success-filter">
                        <option value="">All Results</option>
                        <option value="true">Success</option>
                        <option value="false">Failure</option>
                    </select>
                </div>
            </div>
            <div class="card">
                <div class="card-body" style="padding: 0; overflow-x: auto;">
                    <div id="audit-list"></div>
                </div>
            </div>
        `;

        document.getElementById('audit-action-filter').addEventListener('change', (e) => {
            state.filters.auditAction = e.target.value;
            renderAuditList(auditLogs);
        });

        document.getElementById('audit-user-filter').addEventListener('change', (e) => {
            state.filters.auditUser = e.target.value;
            renderAuditList(auditLogs);
        });

        document.getElementById('audit-success-filter').addEventListener('change', (e) => {
            state.filters.auditSuccess = e.target.value;
            renderAuditList(auditLogs);
        });

        renderAuditList(auditLogs);
    }

    function renderAuditList(logs) {
        const filtered = logs.filter(log => {
            if (state.filters.auditAction && log.actionType !== state.filters.auditAction) return false;
            if (state.filters.auditUser && log.actorUserId !== state.filters.auditUser) return false;
            if (state.filters.auditSuccess !== '' && String(log.success) !== state.filters.auditSuccess) return false;
            return true;
        });

        const listContainer = document.getElementById('audit-list');

        if (filtered.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">&#128220;</div>
                    <h3>No audit entries found</h3>
                </div>
            `;
            return;
        }

        listContainer.innerHTML = `
            <table class="audit-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>Result</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    ${filtered.slice(0, 100).map(log => `
                        <tr>
                            <td>${formatDate(log.timestamp)}</td>
                            <td>${escapeHtml(log.actorName || 'System')}</td>
                            <td>${escapeHtml(log.actionType)}</td>
                            <td>${escapeHtml(log.targetType)}: ${escapeHtml(log.targetId)}</td>
                            <td><span class="${log.success ? 'audit-success' : 'audit-failure'}">${log.success ? 'Success' : 'Failure'}</span></td>
                            <td><span class="audit-detail" title="${escapeHtml(log.detail)}">${escapeHtml(log.detail)}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            ${filtered.length > 100 ? `<p style="padding: 16px; text-align: center; color: var(--text-muted);">Showing first 100 of ${filtered.length} entries</p>` : ''}
        `;
    }

    // ===== Data Import/Export =====
    function initDataActions() {
        // Export
        document.getElementById('export-data-btn').addEventListener('click', async () => {
            try {
                const data = {
                    exportedAt: new Date().toISOString(),
                    version: '2.0',
                    users: await dbGetAll(STORES.USERS),
                    requests: await dbGetAll(STORES.REQUESTS),
                    audit: await dbGetAll(STORES.AUDIT)
                };

                // Remove sensitive password data from export
                data.users = data.users.map(u => ({
                    ...u,
                    passwordHash: '[REDACTED]',
                    passwordSalt: '[REDACTED]'
                }));

                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `triarq-iam-export-${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('Data exported successfully', 'success');
            } catch (error) {
                console.error('Export error:', error);
                showToast('Failed to export data', 'error');
            }
        });

        // Import
        document.getElementById('import-data-btn').addEventListener('click', () => {
            if (!canManageUsers()) {
                showToast('Only admins can import data', 'error');
                return;
            }
            document.getElementById('import-file-input').click();
        });

        document.getElementById('import-file-input').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            if (!confirm('This will replace ALL existing data. Are you sure?')) {
                e.target.value = '';
                return;
            }

            try {
                const text = await file.text();
                const data = JSON.parse(text);

                if (!data.version || !data.requests) {
                    throw new Error('Invalid data format');
                }

                // Clear existing data
                await dbClear(STORES.REQUESTS);
                await dbClear(STORES.AUDIT);

                // Import requests
                for (const req of data.requests) {
                    await dbPut(STORES.REQUESTS, req);
                }

                // Import audit if present
                if (data.audit) {
                    for (const log of data.audit) {
                        await dbPut(STORES.AUDIT, log);
                    }
                }

                await loadAllData();
                broadcastDataChange();
                showToast(`Imported ${data.requests.length} requests`, 'success');

                if (state.currentView) {
                    navigateTo(state.currentView);
                }
            } catch (error) {
                console.error('Import error:', error);
                showToast('Failed to import data. Check file format.', 'error');
            }

            e.target.value = '';
        });

        // Load sample requests
        document.getElementById('load-sample-btn').addEventListener('click', async () => {
            const sampleRequests = generateSampleRequests();
            try {
                for (const req of sampleRequests) {
                    await dbPut(STORES.REQUESTS, req);
                }
                await loadAllData();
                broadcastDataChange();
                showToast(`Loaded ${sampleRequests.length} sample requests`, 'success');

                if (state.currentView) {
                    navigateTo(state.currentView);
                }
            } catch (error) {
                console.error('Failed to load sample data:', error);
                showToast('Failed to load sample data', 'error');
            }
        });

        // Reset database
        document.getElementById('reset-db-btn').addEventListener('click', resetDatabase);
    }

    function generateSampleRequests() {
        const now = new Date();
        const employees = state.users.filter(u => !u.isIam);
        const iamUsers = state.users.filter(u => u.isIam);

        if (employees.length === 0) return [];

        const samples = [
            {
                requester: employees[0],
                department: 'Engineering',
                system: 'GitHub',
                environment: 'Prod',
                requestType: 'Add',
                role: 'Write access to main repository',
                justification: 'Need to contribute to the main codebase for the Q2 feature release.',
                urgency: 'Normal',
                status: 'New',
                daysAgo: 2
            },
            {
                requester: employees[1] || employees[0],
                department: 'Finance',
                system: 'Data Warehouse / BI',
                environment: 'Prod',
                requestType: 'Add',
                role: 'Read access to financial reports',
                justification: 'Required for monthly financial analysis and reporting to leadership.',
                urgency: 'High',
                status: 'In Review',
                assignee: iamUsers[0],
                daysAgo: 5
            },
            {
                requester: employees[0],
                department: 'Engineering',
                system: 'AWS Console',
                environment: 'Non-Prod',
                requestType: 'Add',
                role: 'EC2 and S3 management permissions',
                justification: 'Setting up new development environment for mobile team.',
                urgency: 'High',
                status: 'Completed',
                assignee: iamUsers[1] || iamUsers[0],
                daysAgo: 10
            }
        ];

        return samples.map((sample, index) => {
            const createdAt = new Date(now.getTime() - sample.daysAgo * 24 * 60 * 60 * 1000).toISOString();
            const updatedAt = new Date(now.getTime() - (sample.daysAgo - 1) * 24 * 60 * 60 * 1000).toISOString();

            const request = {
                id: `REQ-${String(100001 + index).padStart(6, '0')}`,
                createdAt,
                updatedAt,
                requesterUserId: sample.requester.userId,
                requesterName: sample.requester.name,
                requesterEmail: sample.requester.email,
                department: sample.department,
                applicationOrSystem: sample.system,
                applicationOtherText: '',
                environment: sample.environment,
                requestType: sample.requestType,
                requestedRoleOrPermission: sample.role,
                justification: sample.justification,
                urgency: sample.urgency,
                status: sample.status,
                iamAssigneeUserId: sample.assignee?.userId || null,
                iamAssigneeName: sample.assignee?.name || null,
                iamComments: [],
                employeeComments: [],
                statusHistory: [{
                    status: 'New',
                    changedByUserId: sample.requester.userId,
                    changedByName: sample.requester.name,
                    changedAt: createdAt,
                    note: 'Request submitted'
                }]
            };

            if (sample.status !== 'New') {
                request.statusHistory.push({
                    status: sample.status,
                    changedByUserId: sample.assignee?.userId,
                    changedByName: sample.assignee?.name || 'IAM Team',
                    changedAt: updatedAt,
                    note: `Status changed to ${sample.status}`
                });
            }

            return request;
        });
    }

    // ===== Event Listeners =====
    function initEventListeners() {
        // Logout button
        document.getElementById('logout-btn').addEventListener('click', async () => {
            await logout();
            broadcastLogout();
        });

        // Modal close on overlay click
        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) hideModal();
        });

        // ESC key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const overlay = document.getElementById('modal-overlay');
                if (!overlay.classList.contains('hidden')) hideModal();
            }
        });
    }

    // ===== Initialize Application =====
    async function init() {
        try {
            await openDatabase();
            console.log('Database opened');

            // Seed default users if needed
            await seedDefaultUsers();

            // Initialize broadcast channel
            initBroadcastChannel();

            // Initialize UI
            initLoginForm();
            initDataActions();
            initEventListeners();

            // Check for existing session
            const validSession = await validateSession();
            if (validSession) {
                await initMainApp();
            } else {
                showLoginScreen();
            }
        } catch (error) {
            console.error('Failed to initialize application:', error);
            showToast('Failed to initialize. Try refreshing.', 'error');
        }
    }

    // Start the application
    init();
})();
