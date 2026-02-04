/**
 * Unified Theme Module for QuickProbe
 * Manages DaisyUI theme application and cross-window synchronization.
 * 
 * Ensures all windows (Login, Dashboard, Hosts, About, Options) apply
 * the same theme consistently, with no flash of unstyled content (FOUC).
 */

(function () {
    'use strict';

    const SETTINGS_KEY = 'quickprobe_settings';
    const VALID_THEMES = [
        'system', 'dark', 'light', 'cupcake', 'bumblebee', 'emerald', 'corporate',
        'synthwave', 'retro', 'cyberpunk', 'valentine', 'halloween', 'garden',
        'forest', 'aqua', 'lofi', 'pastel', 'fantasy', 'wireframe', 'black',
        'luxury', 'dracula', 'cmyk', 'autumn', 'business', 'acid', 'lemonade',
        'night', 'coffee', 'winter', 'dim', 'nord', 'sunset'
    ];

    let debugLogged = false; // Log theme application once per window

    /**
     * Resolve 'system' theme to actual light/dark based on OS preference.
     * Validate theme names against DaisyUI's 32 themes.
     */
    function resolveTheme(theme) {
        if (theme === 'system') {
            try {
                const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
                return prefersDark ? 'dark' : 'light';
            } catch (e) {
                console.warn('[ThemeModule] matchMedia failed, defaulting to dark:', e);
                return 'dark';
            }
        }

        // Validate against known DaisyUI themes
        if (VALID_THEMES.includes(theme)) {
            return theme;
        }

        console.warn('[ThemeModule] Invalid theme name:', theme, '- falling back to dark');
        return 'dark';
    }

    /**
     * Read theme setting from localStorage.
     * Returns the raw theme value (may be 'system') or fallback 'system'.
     */
    function getStoredTheme() {
        try {
            const settingsStr = localStorage.getItem(SETTINGS_KEY);
            if (!settingsStr) {
                return 'system'; // Default when no settings exist
            }
            const settings = JSON.parse(settingsStr);
            return settings.theme || 'system';
        } catch (e) {
            console.warn('[ThemeModule] Failed to read stored theme:', e);
            return 'system';
        }
    }

    /**
     * Apply theme to the document.
     * Resolves 'system' to light/dark, sets data-theme attribute on <html>.
     */
    function applyTheme(theme) {
        const resolved = resolveTheme(theme);
        document.documentElement.setAttribute('data-theme', resolved);

        // Log every theme change for visibility
        console.log('[ThemeModule] Theme applied:', resolved, '(from setting:', theme + ')');
    }

    /**
     * Subscribe to theme updates from other windows and OS theme changes.
     * Sets up:
     * - localStorage 'storage' event (cross-window sync)
     * - Tauri 'settings-updated' event (if available)
     * - OS theme change listener (for 'system' theme)
     * 
     * @param {string} [initialTheme] - Optional theme to apply immediately. If not provided, reads from localStorage.
     */
    function subscribeToThemeUpdates(initialTheme) {
        console.log('[ThemeModule] subscribeToThemeUpdates called - setting up listeners');
        
        // Apply the current theme immediately to ensure consistency
        const currentTheme = initialTheme !== undefined ? initialTheme : getStoredTheme();
        applyTheme(currentTheme);
        
        // Storage event: fires when OTHER windows change localStorage
        window.addEventListener('storage', (e) => {
            if (e.key === SETTINGS_KEY && e.newValue) {
                console.log('[ThemeModule] Storage event received, key:', e.key);
                try {
                    const settings = JSON.parse(e.newValue);
                    if (settings.theme) {
                        console.log('[ThemeModule] Applying theme from storage event:', settings.theme);
                        applyTheme(settings.theme);
                    }
                } catch (err) {
                    console.warn('[ThemeModule] Failed to apply theme from storage event:', err);
                }
            }
        });

        // Tauri event: fires for all windows including sender
        if (window.__TAURI__?.event?.listen) {
            window.__TAURI__.event.listen('settings-updated', (event) => {
                console.log('[ThemeModule] Tauri event received: settings-updated', event.payload);
                try {
                    // Re-read from localStorage (source of truth)
                    const theme = getStoredTheme();
                    console.log('[ThemeModule] Applying theme from Tauri event:', theme);
                    applyTheme(theme);
                } catch (err) {
                    console.warn('[ThemeModule] Failed to apply theme from Tauri event:', err);
                }
            }).catch(err => {
                console.warn('[ThemeModule] Failed to setup settings-updated listener:', err);
            });
        } else {
            console.warn('[ThemeModule] Tauri event API not available');
        }

        // WORKAROUND for Tauri storage event limitations:
        // Also check theme when window gains focus (in case storage event didn't fire)
        window.addEventListener('focus', () => {
            try {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                const storedTheme = getStoredTheme();
                const resolvedStored = resolveTheme(storedTheme);
                if (currentTheme !== resolvedStored) {
                    console.log('[ThemeModule] Window focus - theme mismatch detected, updating from:', currentTheme, 'to:', resolvedStored);
                    applyTheme(storedTheme);
                }
            } catch (e) {
                console.warn('[ThemeModule] Failed to check theme on focus:', e);
            }
        });

        // WORKAROUND: Poll localStorage for theme changes every 2 seconds
        // This handles cases where storage events don't fire cross-window in Tauri
        let lastCheckedTheme = resolveTheme(getStoredTheme());
        setInterval(() => {
            try {
                const storedTheme = getStoredTheme();
                const resolvedStored = resolveTheme(storedTheme);
                if (lastCheckedTheme !== resolvedStored) {
                    console.log('[ThemeModule] Poll detected theme change from:', lastCheckedTheme, 'to:', resolvedStored);
                    applyTheme(storedTheme);
                    lastCheckedTheme = resolvedStored;
                }
            } catch (e) {
                // Silent fail - don't spam console
            }
        }, 2000); // Check every 2 seconds

        // OS theme change listener (for 'system' theme)
        try {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            if (mediaQuery && mediaQuery.addEventListener) {
                mediaQuery.addEventListener('change', () => {
                    const currentTheme = getStoredTheme();
                    if (currentTheme === 'system') {
                        applyTheme('system'); // Re-resolve based on new OS preference
                    }
                });
            }
        } catch (e) {
            console.warn('[ThemeModule] Failed to setup OS theme watcher:', e);
        }
    }

    // Export as global module
    window.ThemeModule = {
        applyTheme,
        subscribeToThemeUpdates,
        getStoredTheme,
        resolveTheme,
        // Expose internals for testing/debugging
        _SETTINGS_KEY: SETTINGS_KEY,
        _VALID_THEMES: VALID_THEMES
    };

    console.log('[ThemeModule] Module loaded and initialized');
})();
