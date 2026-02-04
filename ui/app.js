const { invoke } = window.__TAURI__.core;
const { appWindow } = window.__TAURI__.window;

// E2E Test Mode Detection
// Check localStorage flag (set by test framework) or window global
const isE2ETestMode = window.__QUICKPROBE_E2E_TEST__ === true ||
    localStorage.getItem('quickprobe_e2e_test') === 'true';

if (isE2ETestMode) {
    console.log('[E2E] Test mode enabled - auto-login disabled, window forced visible');
}

// UI Elements
const loginView = document.getElementById('login-view');
const validatingView = document.getElementById('validating-view');
const loginForm = document.getElementById('login-form');
const errorMessage = document.getElementById('error-message');
const countdownMessage = document.getElementById('countdown-message');
const countdownSeconds = document.getElementById('countdown-seconds');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

function disableAutocompleteAll() {
    document.querySelectorAll('input, textarea').forEach((el) => {
        el.setAttribute('autocomplete', 'off');
        if (el.getAttribute('type') === 'text') {
            el.setAttribute('spellcheck', 'false');
        }
    });
}

// State
let countdownTimer = null;
let autoLoginCancelled = false;
let startHiddenEnabled = false;
let autoLoginInProgress = false; // Track if auto-login is initializing
let initializationComplete = false; // Track when initialization is fully complete
let updateCheckComplete = false; // Track when backend update check is done

// View Management
function showView(view) {
    [loginView, validatingView].forEach(v => {
        if (v) v.classList.add('hidden');
    });
    if (view) view.classList.remove('hidden');
}

function showError(message) {
    // Find the span inside the alert for the message text
    const messageSpan = errorMessage.querySelector('.error-text');
    if (messageSpan) {
        messageSpan.textContent = message;
    } else {
        // Fallback if structure changes
        errorMessage.textContent = message;
    }
    errorMessage.classList.remove('hidden');
}

function hideError() {
    errorMessage.classList.add('hidden');
}

function showCountdown() {
    console.log('[Login] showCountdown called, element:', countdownMessage);
    if (countdownMessage) {
        countdownMessage.classList.remove('hidden');
        console.log('[Login] Countdown message shown, classList:', countdownMessage.classList.toString());
    } else {
        console.error('[Login] countdownMessage element is null!');
    }
}

function hideCountdown() {
    console.log('[Login] hideCountdown called');
    if (countdownMessage) {
        countdownMessage.classList.add('hidden');
    }
}

function cancelAutoLogin() {
    console.log('[Login] cancelAutoLogin called, countdownTimer:', !!countdownTimer);
    if (countdownTimer) {
        clearInterval(countdownTimer);
        countdownTimer = null;
    }
    autoLoginCancelled = true;
    hideCountdown();
}

async function loadStartHiddenPreference() {
    console.log('[Login] loadStartHiddenPreference called, __TAURI__:', !!window.__TAURI__, 'invoke:', !!invoke);
    if (!window.__TAURI__ || !invoke) {
        console.log('[Login] loadStartHiddenPreference: Tauri not available, returning false');
        return false;
    }
    try {
        const enabled = await invoke('get_start_hidden_setting');
        console.log('[Login] loadStartHiddenPreference: got value:', enabled);
        return !!enabled;
    } catch (error) {
        console.warn('[Login] Failed to load start-hidden preference', error);
        return false;
    }
}

async function ensureWindowVisible() {
    if (!appWindow) return;
    try {
        await appWindow.show();
        await appWindow.setFocus();
        await appWindow.setSkipTaskbar(false);
    } catch (err) {
        console.warn('Failed to show window', err);
    }
}

async function performAutoLogin() {
    console.log('[Login] performAutoLogin called');
    showView(validatingView);
    try {
        // Auto-login using backend-stored credentials (no password in UI)
        console.log('[Login] Calling login_with_saved_credentials...');
        const result = await invoke('login_with_saved_credentials');
        console.log('[Login] login_with_saved_credentials result:', result);
        if (result && result.success) {
            // Enable options menu on successful login
            try {
                await invoke('enable_options_menu');
            } catch (err) {
                console.warn('Failed to enable options menu:', err);
            }
            // Auto-login: go straight to dashboard, keep window visible on first load
            window.location.href = 'dashboard-all.html';
        } else {
            // Auto-login failed - ensure user sees the error
            console.error('Auto-login failed:', result && result.error);
            await ensureWindowVisible();
            await appWindow.setFocus(); // Ensure window has focus
            
            // Convert technical errors to user-friendly messages
            let errorMsg = (result && result.error) || 'Auto-login failed';
            let userFriendlyMsg = errorMsg;
            
            if (errorMsg.includes('Invalid credentials')) {
                userFriendlyMsg = 'Your password may have expired or been changed. Please login again.';
            } else if (errorMsg.includes('timed out')) {
                userFriendlyMsg = 'Network connection slow or domain controller unreachable. Please try again.';
            } else if (errorMsg.includes('No saved credentials')) {
                userFriendlyMsg = 'No saved credentials found. Please login.';
            } else if (errorMsg.includes('Failed to retrieve credentials')) {
                userFriendlyMsg = 'Unable to access saved credentials. Please login again.';
            }
            
            showError(userFriendlyMsg);
            passwordInput.value = '';
            showView(loginView);
            
            // Set focus to password input if username is filled
            if (usernameInput.value) {
                passwordInput.focus();
            } else {
                usernameInput.focus();
            }
        }
    } catch (error) {
        // Unexpected error during auto-login
        console.error('Auto-login exception:', error);
        await ensureWindowVisible();
        await appWindow.setFocus();
        
        showError(`Auto-login failed: ${error}. Please try logging in manually.`);
        passwordInput.value = '';
        showView(loginView);
        usernameInput.focus();
    }
}

function startCountdown() {
    console.log('[Login] startCountdown called');
    let seconds = 5;
    countdownSeconds.textContent = seconds;
    showCountdown();
    
    countdownTimer = setInterval(async () => {
        seconds--;
        console.log('[Login] Countdown:', seconds);
        if (seconds <= 0) {
            clearInterval(countdownTimer);
            countdownTimer = null;
            hideCountdown();
            console.log('[Login] Countdown complete, performing auto-login');
            await performAutoLogin();
        } else {
            countdownSeconds.textContent = seconds;
        }
    }, 1000);
}

// Initialize app - check for saved credentials
async function initialize(skipTimer = false) {
    console.log('[Login] Initialize called, skipTimer:', skipTimer);
    try {
        startHiddenEnabled = await loadStartHiddenPreference();
        console.log('[Login] startHiddenEnabled:', startHiddenEnabled);
        
        // E2E test mode: always show window and skip auto-login
        if (isE2ETestMode) {
            startHiddenEnabled = false;
            skipTimer = true;
        }

        const result = await invoke('check_saved_credentials');
        console.log('[Login] check_saved_credentials result:', result);
        if (result.has_credentials) {
            // Mark that we're setting up auto-login (prevents focus events from cancelling)
            autoLoginInProgress = true;
            
            // Pre-fill username
            usernameInput.value = result.username || '';
            
            // Show saved password indicator using readonly + descriptive text
            passwordInput.value = '(saved credentials)';
            passwordInput.setAttribute('readonly', 'readonly');
            
            showView(loginView);
            
            console.log('[Login] Decision point - startHiddenEnabled:', startHiddenEnabled, 
                        'skipTimer:', skipTimer, 'autoLoginCancelled:', autoLoginCancelled, 
                        'isE2ETestMode:', isE2ETestMode);
            
            // If start_hidden is enabled and not cancelled, skip countdown and auto-login immediately
            // This ensures the window stays hidden when starting after an update
            if (startHiddenEnabled && !skipTimer && !autoLoginCancelled && !isE2ETestMode) {
                console.log('[Login] start_hidden enabled, auto-login immediately');
                // Auto-login immediately without showing window or countdown
                await performAutoLogin();
                return;
            }
            
            // Start countdown unless coming from logout, user interaction, or E2E test mode
            if (!skipTimer && !autoLoginCancelled && !isE2ETestMode) {
                console.log('[Login] Starting countdown timer');
                startCountdown();
            } else {
                console.log('[Login] Countdown skipped - skipTimer:', skipTimer, 'autoLoginCancelled:', autoLoginCancelled, 'isE2ETestMode:', isE2ETestMode);
            }

            if (!startHiddenEnabled || skipTimer || autoLoginCancelled || isE2ETestMode) {
                console.log('[Login] Ensuring window is visible');
                await ensureWindowVisible();
            }
            
            // Mark initialization as complete AFTER window is visible
            // This prevents focus events during window show from cancelling auto-login
            initializationComplete = true;
            autoLoginInProgress = false;
            console.log('[Login] Initialization complete, autoLoginInProgress set to false');
        } else {
            // No credentials, show login view
            console.log('[Login] No saved credentials found');
            usernameInput.value = '';
            passwordInput.value = '';
            passwordInput.removeAttribute('readonly');
            await ensureWindowVisible();
            showView(loginView);
            initializationComplete = true;
        }
    } catch (error) {
        console.error('[Login] Initialization error:', error);
        await ensureWindowVisible();
        showError(`Initialization error: ${error}`);
        showView(loginView);
        initializationComplete = true;
    }
}

// Cancel auto-login on any interaction (but not during initial setup)
usernameInput.addEventListener('input', () => {
    if (!autoLoginInProgress && initializationComplete) {
        console.log('[Login] Username input - cancelling auto-login');
        cancelAutoLogin();
    }
});
passwordInput.addEventListener('input', () => {
    if (!autoLoginInProgress && initializationComplete) {
        console.log('[Login] Password input - cancelling auto-login');
        cancelAutoLogin();
        // Clear saved credentials indicator when user starts typing
        if (passwordInput.hasAttribute('readonly')) {
            passwordInput.removeAttribute('readonly');
            passwordInput.value = '';
        }
    }
});
usernameInput.addEventListener('focus', () => {
    if (!autoLoginInProgress && initializationComplete) {
        console.log('[Login] Username focus - cancelling auto-login');
        cancelAutoLogin();
    }
});
passwordInput.addEventListener('focus', () => {
    // Ignore focus events during auto-login initialization
    // This prevents browser auto-focus from cancelling auto-login
    if (!autoLoginInProgress && initializationComplete) {
        console.log('[Login] Password focus - cancelling auto-login');
        cancelAutoLogin();
        // Note: We no longer clear the password on focus alone
        // The user must click explicitly or start typing to clear it
    }
});

// Handle click on password field to enable editing
passwordInput.addEventListener('click', (e) => {
    // Only clear when user explicitly clicks on the field (not programmatic focus)
    if (initializationComplete && passwordInput.hasAttribute('readonly')) {
        console.log('[Login] Password click - clearing saved credentials placeholder');
        passwordInput.removeAttribute('readonly');
        passwordInput.value = '';
        passwordInput.focus();
    }
});

// Handle login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    cancelAutoLogin();
    hideError();
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    // Remove readonly if present and check for empty password
    if (passwordInput.hasAttribute('readonly')) {
        showError('Please enter your password');
        passwordInput.removeAttribute('readonly');
        passwordInput.value = '';
        passwordInput.focus();
        return;
    }
    
    if (!username || !password) {
        showError('Username and password are required');
        return;
    }
    
    showView(validatingView);
    
    try {
        const result = await invoke('login', {
            username,
            password
        });
        
        if (result.success) {
            // Enable options menu on successful login
            try {
                await invoke('enable_options_menu');
            } catch (err) {
                console.warn('Failed to enable options menu:', err);
            }
            // Redirect to dashboard and keep window visible
            window.location.href = 'dashboard-all.html';
        } else {
            showError(result.error || 'Login failed');
            showView(loginView);
        }
    } catch (error) {
        showError(`Login error: ${error}`);
        showView(loginView);
    }
});

// Initialize on load
window.addEventListener('DOMContentLoaded', async () => {
    console.log('[Login] DOMContentLoaded fired');
    
    // Set up event listener for update-check-complete (must be done before initialize)
    try {
        if (window.__TAURI__?.event?.listen) {
            window.__TAURI__.event.listen('update-check-complete', (event) => {
                console.log('[Login] Received update-check-complete event:', event.payload);
                updateCheckComplete = true;
            });
        }
    } catch (err) {
        console.warn('[Login] Failed to set up update-check-complete listener:', err);
    }
    
    disableAutocompleteAll();
    // Check if we should skip auto-login (e.g., after logout)
    const urlParams = new URLSearchParams(window.location.search);
    const skipAutoLogin = urlParams.get('skipAutoLogin') === 'true';
    
    if (skipAutoLogin) {
        console.log('[Login] skipAutoLogin URL parameter detected');
        autoLoginCancelled = true;
    }
    
    await initialize();
    console.log('[Login] Initialize completed');

    // Load theme from backend settings (or localStorage fallback)
    let themeToApply = 'system';
    try {
        if (window.__TAURI__?.core?.invoke) {
            const bundle = await window.__TAURI__.core.invoke('settings_get_all');
            if (bundle?.qp_settings) {
                themeToApply = bundle.qp_settings.theme || 'system';
                // Sync to localStorage so all windows stay in sync
                localStorage.setItem('quickprobe_settings', JSON.stringify(bundle.qp_settings));
            }
        } else {
            // Fallback to localStorage
            const settingsStr = localStorage.getItem('quickprobe_settings');
            if (settingsStr) {
                const settings = JSON.parse(settingsStr);
                themeToApply = settings.theme || 'system';
            }
        }
    } catch (err) {
        console.warn('[Login] Failed to load theme settings:', err);
        // Fallback to localStorage
        try {
            const settingsStr = localStorage.getItem('quickprobe_settings');
            if (settingsStr) {
                const settings = JSON.parse(settingsStr);
                themeToApply = settings.theme || 'system';
            }
        } catch (e) {
            // Use default
        }
    }

    // Set up unified theme update listeners AFTER Tauri operations complete
    if (window.ThemeModule?.subscribeToThemeUpdates) {
        window.ThemeModule.subscribeToThemeUpdates(themeToApply);
    }
});
