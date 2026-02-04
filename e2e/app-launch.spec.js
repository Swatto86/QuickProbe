/**
 * QuickProbe E2E Test: Application Launch
 *
 * Tests the basic application startup and window management:
 * - Application starts successfully
 * - Window is visible and focused
 * - Basic DOM structure loads
 * - Tauri API is available
 * 
 * These are the foundational tests that run first to ensure
 * the test environment is working correctly.
 */

describe('QuickProbe Application Launch', () => {
  describe('Initial Window', () => {
    it('should have a valid URL', async () => {
      const url = await browser.getUrl();
      
      // Should be a tauri URL pointing to a local HTML file
      // Tauri 2.x uses http://tauri.localhost/ format
      expect(url).toMatch(/tauri\.localhost/);
      expect(url).toMatch(/\.html/);
    });

    it('should have a document title', async () => {
      const title = await browser.getTitle();
      
      // QuickProbe pages have titles starting with "QuickProbe"
      expect(title).toContain('QuickProbe');
    });

    it('should have a visible body element', async () => {
      const body = await $('body');
      await expect(body).toBeExisting();
      await expect(body).toBeDisplayed();
    });

    it('should have the HTML element with a theme', async () => {
      const html = await $('html');
      await expect(html).toBeExisting();
      
      const theme = await html.getAttribute('data-theme');
      expect(theme).toBeDefined();
      expect(theme.length).toBeGreaterThan(0);
    });
  });

  describe('DaisyUI Theme System', () => {
    it('should have a valid DaisyUI theme applied', async () => {
      const html = await $('html');
      const theme = await html.getAttribute('data-theme');
      
      // Valid DaisyUI themes
      const validThemes = [
        'light', 'dark', 'cupcake', 'bumblebee', 'emerald', 'corporate',
        'synthwave', 'retro', 'cyberpunk', 'valentine', 'halloween', 'garden',
        'forest', 'aqua', 'lofi', 'pastel', 'fantasy', 'wireframe', 'black',
        'luxury', 'dracula', 'cmyk', 'autumn', 'business', 'acid', 'lemonade',
        'night', 'coffee', 'winter', 'dim', 'nord', 'sunset'
      ];
      
      expect(validThemes).toContain(theme);
    });

    it('should have CSS custom properties defined', async () => {
      // Check that DaisyUI CSS variables are present
      const hasPrimaryColor = await browser.execute(() => {
        const root = document.documentElement;
        const style = getComputedStyle(root);
        // DaisyUI uses --p for primary color
        return style.getPropertyValue('--p') !== '';
      });
      
      expect(hasPrimaryColor).toBe(true);
    });
  });

  describe('Tauri Integration', () => {
    it('should have Tauri global object available', async () => {
      const hasTauri = await browser.execute(() => {
        return typeof window.__TAURI__ !== 'undefined';
      });
      
      expect(hasTauri).toBe(true);
    });

    it('should have Tauri invoke function available', async () => {
      const hasInvoke = await browser.execute(() => {
        return typeof window.__TAURI__?.tauri?.invoke === 'function' ||
               typeof window.__TAURI__?.core?.invoke === 'function';
      });
      
      expect(hasInvoke).toBe(true);
    });

    it('should have Tauri event system available', async () => {
      const hasEvent = await browser.execute(() => {
        return typeof window.__TAURI__?.event !== 'undefined';
      });
      
      expect(hasEvent).toBe(true);
    });
  });

  describe('DOM Readiness', () => {
    it('should have fully loaded DOM', async () => {
      const readyState = await browser.execute(() => {
        return document.readyState;
      });
      
      expect(readyState).toBe('complete');
    });

    it('should have stylesheet loaded', async () => {
      const stylesheetLoaded = await browser.execute(() => {
        const styleSheets = document.styleSheets;
        return styleSheets.length > 0;
      });
      
      expect(stylesheetLoaded).toBe(true);
    });

    it('should have scripts executed', async () => {
      // Check that localStorage is accessible (scripts use it)
      const localStorageWorks = await browser.execute(() => {
        try {
          localStorage.setItem('e2e_test_key', 'test');
          const value = localStorage.getItem('e2e_test_key');
          localStorage.removeItem('e2e_test_key');
          return value === 'test';
        } catch (e) {
          return false;
        }
      });
      
      expect(localStorageWorks).toBe(true);
    });
  });

  describe('Window Properties', () => {
    it('should have reasonable window size', async () => {
      const windowSize = await browser.getWindowSize();
      
      // Window should be at least 400x300 (minimum usable size)
      expect(windowSize.width).toBeGreaterThanOrEqual(400);
      expect(windowSize.height).toBeGreaterThanOrEqual(300);
    });

    it('should have responsive meta tag', async () => {
      const viewportMeta = await $('meta[name="viewport"]');
      await expect(viewportMeta).toBeExisting();
      
      const content = await viewportMeta.getAttribute('content');
      expect(content).toContain('width=device-width');
    });

    it('should have UTF-8 charset', async () => {
      const charsetMeta = await $('meta[charset]');
      await expect(charsetMeta).toBeExisting();
      
      const charset = await charsetMeta.getAttribute('charset');
      expect(charset.toLowerCase()).toBe('utf-8');
    });
  });

  describe('Page Content Detection', () => {
    it('should be on a valid QuickProbe page', async () => {
      const url = await browser.getUrl();
      
      // Check for valid QuickProbe pages (login, dashboard-all, hosts, options, about, update-required)
      const isValidPage = 
        url.includes('login') ||
        url.includes('dashboard') ||
        url.includes('hosts') ||
        url.includes('options') ||
        url.includes('about') ||
        url.includes('update');
      
      // Log URL for debugging
      if (!isValidPage) {
        console.log('[Debug] Current URL:', url);
      }
      
      expect(isValidPage).toBe(true);
    });

    it('should have a primary heading', async () => {
      // All pages have at least one h1 or significant heading
      const h1 = await $('h1');
      await expect(h1).toBeExisting();
    });
  });

  describe('Error Detection', () => {
    it('should not have uncaught errors visible on page', async () => {
      // Check that no error overlays or error messages are visible
      // WebdriverIO v7 doesn't support getLogs, so we check DOM instead
      const errorOverlay = await $('.error-overlay');
      const errorExists = await errorOverlay.isExisting();
      
      expect(errorExists).toBe(false);
    });
  });
});
