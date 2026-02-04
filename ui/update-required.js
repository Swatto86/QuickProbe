/**
 * Update Required Window Script
 * 
 * Handles the update UI, fetching update info, and initiating downloads.
 */

// Tauri API - using global __TAURI__ for Tauri v2
const { invoke } = window.__TAURI__.core;
const { exit } = window.__TAURI__.process;

/**
 * @typedef {Object} UpdateInfo
 * @property {boolean} available
 * @property {string} version
 * @property {string} body
 * @property {string} current_version
 * @property {string} release_url
 * @property {string|null} installer_url
 */

/** @type {UpdateInfo|null} */
let updateInfo = null;

/**
 * Show an error message in the UI.
 * @param {string} message 
 */
function showError(message) {
    const errorEl = document.getElementById('error-message');
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.classList.add('visible');
    }
}

/**
 * Hide the error message.
 */
function hideError() {
    const errorEl = document.getElementById('error-message');
    if (errorEl) {
        errorEl.classList.remove('visible');
    }
}

/**
 * Set the download button to loading state.
 * @param {boolean} loading 
 */
function setLoadingState(loading) {
    const btn = document.getElementById('download-btn');
    const content = btn?.querySelector('.btn-content');
    const loadingState = btn?.querySelector('.loading-state');
    
    if (loading) {
        btn?.setAttribute('disabled', 'true');
        content?.classList.add('loading');
        loadingState?.classList.add('active');
    } else {
        btn?.removeAttribute('disabled');
        content?.classList.remove('loading');
        loadingState?.classList.remove('active');
    }
}

/**
 * Update the UI with version information.
 * @param {UpdateInfo} info 
 */
function displayUpdateInfo(info) {
    const currentVersionEl = document.getElementById('current-version');
    const newVersionEl = document.getElementById('new-version');
    const releaseNotesEl = document.getElementById('release-notes');
    
    if (currentVersionEl) {
        currentVersionEl.textContent = `v${info.current_version}`;
    }
    
    if (newVersionEl) {
        newVersionEl.textContent = `v${info.version}`;
    }
    
    if (releaseNotesEl) {
        // Convert markdown-style formatting to plain text for display
        let notes = info.body || '';
        
        // Basic markdown cleanup (headers, bold, etc.)
        notes = notes
            .replace(/^#+\s*/gm, '')  // Remove markdown headers
            .replace(/\*\*(.*?)\*\*/g, '$1')  // Remove bold
            .replace(/__(.*?)__/g, '$1')
            .replace(/\*(.*?)\*/g, '$1')  // Remove italic
            .replace(/_(.*?)_/g, '$1')
            .trim();
        
        releaseNotesEl.textContent = notes;
    }
}

/**
 * Initialize the update window.
 */
async function init() {
    try {
        // Fetch update info from the backend
        updateInfo = await invoke('check_for_update');
        
        if (updateInfo) {
            displayUpdateInfo(updateInfo);
        }
    } catch (error) {
        console.error('Failed to get update info:', error);
        showError(`Failed to check for updates: ${error}`);
    }
}

/**
 * Handle quit button click.
 */
async function handleQuit() {
    try {
        await exit(0);
    } catch (error) {
        console.error('Failed to exit:', error);
        // Fallback: try window close
        window.close();
    }
}

/**
 * Handle download button click.
 */
async function handleDownload() {
    if (!updateInfo) {
        showError('Update information not available. Please try again.');
        return;
    }
    
    hideError();
    setLoadingState(true);
    
    try {
        // Call the backend to download and install
        await invoke('download_and_install_update', { updateInfo });
        
        // Give a moment for the installer to start, then exit
        setTimeout(async () => {
            try {
                await exit(0);
            } catch {
                window.close();
            }
        }, 1000);
    } catch (error) {
        console.error('Download failed:', error);
        setLoadingState(false);
        showError(`Download failed: ${error}`);
    }
}

// Set up event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const quitBtn = document.getElementById('quit-btn');
    const downloadBtn = document.getElementById('download-btn');
    
    quitBtn?.addEventListener('click', handleQuit);
    downloadBtn?.addEventListener('click', handleDownload);
    
    // Subscribe to theme updates for cross-window sync
    if (window.ThemeModule?.subscribeToThemeUpdates) {
        const storedTheme = window.ThemeModule.getStoredTheme?.() || 'system';
        window.ThemeModule.subscribeToThemeUpdates(storedTheme);
        console.log('[UpdateRequired] ThemeModule subscribed with theme:', storedTheme);
    } else {
        console.warn('[UpdateRequired] ThemeModule not available for theme subscription');
    }
    
    // Initialize
    init();
});
