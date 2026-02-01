// =====================================================
// Supabase Client Configuration
// =====================================================
// IMPORTANT: Replace these placeholders with your actual values
// Find them at: Supabase Dashboard → Settings → API
// =====================================================

const SUPABASE_URL = "https://<PROJECT_REF>.supabase.co";
const SUPABASE_ANON_KEY = "<ANON_OR_PUBLISHABLE_KEY>";

// Initialize client (supabase-js loaded via CDN)
window.supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// =====================================================
// Auth Helper Functions
// =====================================================

async function supabaseGetUser() {
    const { data: { user }, error } = await window.supabaseClient.auth.getUser();
    if (error) {
        console.error('Error getting user:', error);
        return null;
    }
    return user;
}

async function supabaseGetSession() {
    const { data: { session }, error } = await window.supabaseClient.auth.getSession();
    if (error) {
        console.error('Error getting session:', error);
        return null;
    }
    return session;
}

async function supabaseSignInWithEmail(email) {
    const redirectUrl = window.location.origin + window.location.pathname;
    const { data, error } = await window.supabaseClient.auth.signInWithOtp({
        email: email,
        options: {
            emailRedirectTo: redirectUrl
        }
    });
    if (error) {
        console.error('Sign in error:', error);
        throw error;
    }
    return data;
}

async function supabaseSignOut() {
    const { error } = await window.supabaseClient.auth.signOut();
    if (error) {
        console.error('Sign out error:', error);
        throw error;
    }
}

// =====================================================
// Profile Functions
// =====================================================

async function supabaseGetProfile(userId) {
    const { data, error } = await window.supabaseClient
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .single();
    if (error && error.code !== 'PGRST116') {
        console.error('Error getting profile:', error);
    }
    return data;
}

async function supabaseUpdateProfile(userId, updates) {
    const { data, error } = await window.supabaseClient
        .from('profiles')
        .update(updates)
        .eq('id', userId)
        .select()
        .single();
    if (error) {
        console.error('Error updating profile:', error);
        throw error;
    }
    return data;
}

// =====================================================
// Request Functions
// =====================================================

async function supabaseGetRequests() {
    const { data, error } = await window.supabaseClient
        .from('requests')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) {
        console.error('Error getting requests:', error);
        throw error;
    }
    return data || [];
}

async function supabaseGetRequestById(requestId) {
    const { data, error } = await window.supabaseClient
        .from('requests')
        .select('*')
        .eq('id', requestId)
        .single();
    if (error) {
        console.error('Error getting request:', error);
        throw error;
    }
    return data;
}

async function supabaseCreateRequest(request) {
    const { data, error } = await window.supabaseClient
        .from('requests')
        .insert(request)
        .select()
        .single();
    if (error) {
        console.error('Error creating request:', error);
        throw error;
    }
    return data;
}

async function supabaseUpdateRequest(requestId, updates) {
    const { data, error } = await window.supabaseClient
        .from('requests')
        .update(updates)
        .eq('id', requestId)
        .select()
        .single();
    if (error) {
        console.error('Error updating request:', error);
        throw error;
    }
    return data;
}

// =====================================================
// Request Events Functions
// =====================================================

async function supabaseGetRequestEvents(requestId) {
    const { data, error } = await window.supabaseClient
        .from('request_events')
        .select('*')
        .eq('request_id', requestId)
        .order('created_at', { ascending: true });
    if (error) {
        console.error('Error getting events:', error);
        throw error;
    }
    return data || [];
}

async function supabaseAddRequestEvent(event) {
    const { data, error } = await window.supabaseClient
        .from('request_events')
        .insert(event)
        .select()
        .single();
    if (error) {
        console.error('Error adding event:', error);
        throw error;
    }
    return data;
}

// =====================================================
// Realtime Subscriptions
// =====================================================

let requestsSubscription = null;

function supabaseSubscribeToRequests(callback) {
    // Unsubscribe from existing subscription
    if (requestsSubscription) {
        requestsSubscription.unsubscribe();
    }

    requestsSubscription = window.supabaseClient
        .channel('requests-changes')
        .on('postgres_changes',
            { event: '*', schema: 'public', table: 'requests' },
            (payload) => {
                console.log('Request change:', payload);
                callback(payload);
            }
        )
        .subscribe();

    return requestsSubscription;
}

function supabaseUnsubscribeFromRequests() {
    if (requestsSubscription) {
        requestsSubscription.unsubscribe();
        requestsSubscription = null;
    }
}

// =====================================================
// Auth State Change Listener
// =====================================================

function supabaseOnAuthStateChange(callback) {
    return window.supabaseClient.auth.onAuthStateChange((event, session) => {
        console.log('Auth state changed:', event);
        callback(event, session);
    });
}
