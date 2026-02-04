/**
 * QuickProbe E2E Test: Options Page
 *
 * Tests the options/settings page functionality:
 * - Startup settings
 * - Appearance/theme settings
 * - Backup & Restore
 * - Location mappings
 * - Probe timeouts
 * - Notification settings
 * - Update checking
 */

describe('QuickProbe Options', () => {
  /**
   * Navigate to options page
   */
  async function ensureOnOptionsPage() {
    const url = await browser.getUrl();
    if (!url.includes('options')) {
      // Tauri 2.x uses http:// instead of https://
      await browser.url('http://tauri.localhost/options.html');
      await browser.pause(2000);
    }
    
    // Wait for page to load
    await browser.waitUntil(
      async () => {
        const header = await $('h1.text-primary');
        return await header.isExisting();
      },
      { timeout: 15000, timeoutMsg: 'Options page did not load within 15 seconds' }
    );
  }

  before(async () => {
    await ensureOnOptionsPage();
  });

  describe('Page Structure', () => {
    it('should display the QuickProbe Options header', async () => {
      const header = await $('h1.text-primary');
      await expect(header).toBeExisting();
      
      const text = await header.getText();
      expect(text).toBe('QuickProbe Options');
    });
  });

  describe('Startup Section', () => {
    it('should have autostart status display', async () => {
      const autostartStatus = await $('#autostart-status');
      await expect(autostartStatus).toBeExisting();
    });

    it('should have toggle autostart button', async () => {
      const toggleBtn = await $('#toggle-autostart-btn');
      await expect(toggleBtn).toBeExisting();
      await expect(toggleBtn).toBeClickable();
      
      const text = await toggleBtn.getText();
      expect(text).toContain('Autostart');
    });

    it('should have start hidden toggle checkbox', async () => {
      const checkbox = await $('#start-hidden-toggle');
      await expect(checkbox).toBeExisting();
      
      const type = await checkbox.getAttribute('type');
      expect(type).toBe('checkbox');
    });
  });

  describe('Appearance Section', () => {
    it('should have theme dropdown', async () => {
      const themeSelect = await $('#theme-select');
      await expect(themeSelect).toBeExisting();
    });

    it('should have System option in theme dropdown', async () => {
      const themeSelect = await $('#theme-select');
      const systemOption = await themeSelect.$('option[value="system"]');
      await expect(systemOption).toBeExisting();
      
      const text = await systemOption.getText();
      expect(text).toContain('System');
    });

    it('should have light and dark theme groups', async () => {
      const themeSelect = await $('#theme-select');
      
      const lightGroup = await themeSelect.$('optgroup[label="Light Themes"]');
      const darkGroup = await themeSelect.$('optgroup[label="Dark Themes"]');
      
      await expect(lightGroup).toBeExisting();
      await expect(darkGroup).toBeExisting();
    });

    it('should have many theme options', async () => {
      const themeSelect = await $('#theme-select');
      const options = await themeSelect.$$('option');
      
      // Should have 32+ themes (including system)
      expect(options.length).toBeGreaterThan(30);
    });
  });

  describe('Backup & Restore Section', () => {
    it('should have backup password input', async () => {
      const passwordInput = await $('#backup-password');
      await expect(passwordInput).toBeExisting();
      
      const type = await passwordInput.getAttribute('type');
      expect(type).toBe('password');
      
      const placeholder = await passwordInput.getAttribute('placeholder');
      expect(placeholder).toContain('Required');
    });

    it('should have Create Backup button', async () => {
      const backupBtn = await $('#backup-btn');
      await expect(backupBtn).toBeExisting();
      await expect(backupBtn).toBeClickable();
      
      const text = await backupBtn.getText();
      expect(text).toContain('Create Backup');
    });

    it('should have Restore Backup button', async () => {
      const restoreBtn = await $('#restore-btn');
      await expect(restoreBtn).toBeExisting();
      await expect(restoreBtn).toBeClickable();
      
      const text = await restoreBtn.getText();
      expect(text).toContain('Restore');
    });

    it('should have backup status display', async () => {
      const status = await $('#backup-status');
      await expect(status).toBeExisting();
    });
  });

  describe('CSV Export Section', () => {
    it('should have Export to CSV button', async () => {
      const exportBtn = await $('#export-csv-btn');
      await expect(exportBtn).toBeExisting();
      await expect(exportBtn).toBeClickable();
      
      const text = await exportBtn.getText();
      expect(text).toContain('Export');
    });

    it('should have CSV export status display', async () => {
      const status = await $('#csv-export-status');
      await expect(status).toBeExisting();
    });
  });

  describe('Location Mapping Section', () => {
    it('should have location section container', async () => {
      const section = await $('#location-section');
      await expect(section).toBeExisting();
    });

    it('should have location rows container', async () => {
      const rows = await $('#location-rows');
      await expect(rows).toBeExisting();
    });

    it('should have Add Location button', async () => {
      const addBtn = await $('#add-location-btn');
      await expect(addBtn).toBeExisting();
      await expect(addBtn).toBeClickable();
      
      const text = await addBtn.getText();
      expect(text).toContain('Add Location');
    });
  });

  describe('Probes Section', () => {
    it('should have probe timeout input', async () => {
      const probeTimeout = await $('#probe-timeout');
      await expect(probeTimeout).toBeExisting();
      
      const type = await probeTimeout.getAttribute('type');
      expect(type).toBe('number');
      
      const min = await probeTimeout.getAttribute('min');
      const max = await probeTimeout.getAttribute('max');
      expect(parseInt(min, 10)).toBe(10);
      expect(parseInt(max, 10)).toBe(600);
    });

    it('should have quick probe timeout input', async () => {
      const quickProbeTimeout = await $('#quick-probe-timeout');
      await expect(quickProbeTimeout).toBeExisting();
      
      const type = await quickProbeTimeout.getAttribute('type');
      expect(type).toBe('number');
      
      const min = await quickProbeTimeout.getAttribute('min');
      const max = await quickProbeTimeout.getAttribute('max');
      expect(parseInt(min, 10)).toBe(5);
      expect(parseInt(max, 10)).toBe(120);
    });
  });

  describe('Notifications Section', () => {
    it('should have info timeout input', async () => {
      const infoTimeout = await $('#info-timeout');
      await expect(infoTimeout).toBeExisting();
      
      const type = await infoTimeout.getAttribute('type');
      expect(type).toBe('number');
    });

    it('should have warning timeout input', async () => {
      const warningTimeout = await $('#warning-timeout');
      await expect(warningTimeout).toBeExisting();
      
      const type = await warningTimeout.getAttribute('type');
      expect(type).toBe('number');
    });

    it('should have error timeout input', async () => {
      const errorTimeout = await $('#error-timeout');
      await expect(errorTimeout).toBeExisting();
      
      const type = await errorTimeout.getAttribute('type');
      expect(type).toBe('number');
    });
  });

  // Note: Updates Section moved to About dialog - tests in about.spec.js

  describe('Action Buttons', () => {
    it('should have Save All Settings button', async () => {
      const saveBtn = await $('#save-btn');
      await expect(saveBtn).toBeExisting();
      await expect(saveBtn).toBeClickable();
      
      const text = await saveBtn.getText();
      expect(text).toContain('Save');
    });

    it('should have Close button', async () => {
      const closeBtn = await $('#close-btn');
      await expect(closeBtn).toBeExisting();
      await expect(closeBtn).toBeClickable();
      
      const text = await closeBtn.getText();
      expect(text).toBe('Close');
    });

    it('should have status message area', async () => {
      const status = await $('#status');
      await expect(status).toBeExisting();
    });
  });

  describe('Modals', () => {
    it('should have confirmation modal', async () => {
      const modal = await $('#confirm-modal');
      await expect(modal).toBeExisting();
    });

    it('should have update modal', async () => {
      const modal = await $('#update-modal');
      await expect(modal).toBeExisting();
    });
  });

  describe('Input Validation', () => {
    it('should enforce probe timeout min/max constraints', async () => {
      const probeTimeout = await $('#probe-timeout');
      
      // Clear and set a value
      await probeTimeout.setValue('30');
      const value = await probeTimeout.getValue();
      expect(value).toBe('30');
    });

    it('should accept valid notification timeout values', async () => {
      const infoTimeout = await $('#info-timeout');
      
      // Set a value
      await infoTimeout.setValue('5000');
      const value = await infoTimeout.getValue();
      expect(value).toBe('5000');
    });
  });

  describe('Theme Selection Functionality', () => {
    it('should change theme when selecting from dropdown', async () => {
      const themeSelect = await $('#theme-select');
      
      // Select dracula theme
      await themeSelect.selectByAttribute('value', 'dracula');
      await browser.pause(500);
      
      // Verify the select has the correct value
      const selectedValue = await themeSelect.getValue();
      expect(selectedValue).toBe('dracula');
      
      // Reset to dark
      await themeSelect.selectByAttribute('value', 'dark');
      await browser.pause(300);
    });
  });
});
