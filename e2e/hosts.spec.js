/**
 * QuickProbe E2E Test: Hosts Editor
 *
 * Tests the host editing functionality:
 * - Host list display
 * - Add/Edit/Delete hosts form
 * - Search functionality
 * - Group management
 * - Service templates
 */

describe('QuickProbe Hosts Editor', () => {
  /**
   * Dismiss any blocking modals (confirmation dialogs, etc.)
   */
  async function dismissBlockingModals() {
    // Check for confirmation modal backdrop
    const confirmBackdrop = await $('#confirm-modal-backdrop');
    if (await confirmBackdrop.isDisplayed()) {
      // Try to click OK button to dismiss
      const okBtn = await $('#confirm-modal-ok');
      if (await okBtn.isExisting() && await okBtn.isDisplayed()) {
        await okBtn.click();
        await browser.pause(300);
      }
    }
    
    // Also check for scan modal that might be open
    const scanModal = await $('#scan-modal');
    if (await scanModal.isExisting()) {
      const isOpen = await scanModal.getAttribute('open');
      if (isOpen) {
        const cancelBtn = await $('#scan-cancel');
        if (await cancelBtn.isExisting() && await cancelBtn.isDisplayed()) {
          await cancelBtn.click();
          await browser.pause(300);
        }
      }
    }
  }
  
  /**
   * Navigate to hosts page
   */
  async function ensureOnHostsPage() {
    const url = await browser.getUrl();
    if (!url.includes('hosts')) {
      // Tauri 2.x uses http:// instead of https://
      await browser.url('http://tauri.localhost/hosts.html');
      await browser.pause(2000);
    }
    
    // Dismiss any blocking modals that may appear
    await dismissBlockingModals();
    
    // Wait for page to load
    await browser.waitUntil(
      async () => {
        const hostList = await $('#host-list');
        return await hostList.isExisting();
      },
      { timeout: 15000, timeoutMsg: 'Hosts page did not load within 15 seconds' }
    );
    
    // Dismiss modals again after page load
    await dismissBlockingModals();
  }

  before(async () => {
    await ensureOnHostsPage();
  });
  
  // Ensure modals are dismissed before each test
  beforeEach(async () => {
    await dismissBlockingModals();
  });

  describe('Page Structure', () => {
    it('should display the Host Editor header', async () => {
      const header = await $('h1.text-primary');
      await expect(header).toBeExisting();
      
      const text = await header.getText();
      expect(text).toBe('Host Editor');
    });

    it('should have Back to Dashboard button', async () => {
      const backBtn = await $('#back-dashboard');
      await expect(backBtn).toBeExisting();
      await expect(backBtn).toBeClickable();
      
      const text = await backBtn.getText();
      expect(text).toContain('Back to Dashboard');
    });

    it('should have Refresh Status button', async () => {
      const refreshBtn = await $('#check-status-all');
      await expect(refreshBtn).toBeExisting();
      await expect(refreshBtn).toBeClickable();
      
      const text = await refreshBtn.getText();
      expect(text).toContain('Refresh Status');
    });

    it('should have Delete All Hosts button', async () => {
      const deleteBtn = await $('#delete-all-hosts');
      await expect(deleteBtn).toBeExisting();
      await expect(deleteBtn).toBeClickable();
      
      const text = await deleteBtn.getText();
      expect(text).toContain('Delete All');
    });

    it('should have Scan AD button', async () => {
      const scanBtn = await $('#scan-ad');
      await expect(scanBtn).toBeExisting();
      await expect(scanBtn).toBeClickable();
      
      const text = await scanBtn.getText();
      expect(text).toContain('Scan AD');
    });
  });

  describe('Host Search', () => {
    it('should have a search input field', async () => {
      const searchInput = await $('#host-search');
      await expect(searchInput).toBeExisting();
      
      const placeholder = await searchInput.getAttribute('placeholder');
      expect(placeholder).toContain('Search hosts');
    });

    it('should have a clear search button', async () => {
      const clearBtn = await $('#clear-host-search');
      await expect(clearBtn).toBeExisting();
      
      const text = await clearBtn.getText();
      expect(text).toBe('Clear');
    });

    it('should accept search input', async () => {
      const searchInput = await $('#host-search');
      await searchInput.click();
      await searchInput.setValue('test-server');
      await browser.pause(300);
      
      const value = await searchInput.getValue();
      expect(value).toBe('test-server');
      
      // Clear after test
      const clearBtn = await $('#clear-host-search');
      await clearBtn.click();
      await browser.pause(200);
    });
  });

  describe('Host Form', () => {
    it('should have a form title', async () => {
      const formTitle = await $('#form-title');
      await expect(formTitle).toBeExisting();
      
      const text = await formTitle.getText();
      // Should be "Add Host" when not editing
      expect(text).toBe('Add Host');
    });

    it('should have host name input field', async () => {
      const hostNameInput = await $('#host-name');
      await expect(hostNameInput).toBeExisting();
      
      const placeholder = await hostNameInput.getAttribute('placeholder');
      expect(placeholder).toContain('SERVER');
      
      const required = await hostNameInput.getAttribute('required');
      expect(required).toBe('true');
    });

    it('should have host notes input field', async () => {
      const notesInput = await $('#host-notes');
      await expect(notesInput).toBeExisting();
      
      const placeholder = await notesInput.getAttribute('placeholder');
      expect(placeholder).toContain('Role');
    });

    it('should have host group dropdown', async () => {
      const groupSelect = await $('#host-group');
      await expect(groupSelect).toBeExisting();
      
      // Should have at least the "(No Group)" option
      const options = await groupSelect.$$('option');
      expect(options.length).toBeGreaterThanOrEqual(1);
      
      const firstOption = await options[0].getText();
      expect(firstOption).toContain('No Group');
    });

    it('should have host OS dropdown', async () => {
      const osSelect = await $('#host-os');
      await expect(osSelect).toBeExisting();
      
      // Check for Windows and Linux options
      const windowsOption = await osSelect.$('option[value="Windows"]');
      const linuxOption = await osSelect.$('option[value="Linux"]');
      
      await expect(windowsOption).toBeExisting();
      await expect(linuxOption).toBeExisting();
    });

    it('should have service template dropdown', async () => {
      const templateSelect = await $('#service-template');
      await expect(templateSelect).toBeExisting();
      
      // Should have a default "Choose a template..." option
      const options = await templateSelect.$$('option');
      expect(options.length).toBeGreaterThanOrEqual(1);
    });

    it('should have Browse Services button', async () => {
      const browseBtn = await $('#browse-services-btn');
      await expect(browseBtn).toBeExisting();
      
      const text = await browseBtn.getText();
      expect(text).toContain('Browse Services');
    });

    it('should have services textarea', async () => {
      const servicesTextarea = await $('#host-services');
      await expect(servicesTextarea).toBeExisting();
      
      const placeholder = await servicesTextarea.getAttribute('placeholder');
      expect(placeholder).toContain('WinRM');
    });

    it('should have Save and Cancel buttons', async () => {
      const saveBtn = await $('#host-form button[type="submit"]');
      const cancelBtn = await $('#cancel-edit');
      
      await expect(saveBtn).toBeExisting();
      await expect(cancelBtn).toBeExisting();
      
      const saveText = await saveBtn.getText();
      const cancelText = await cancelBtn.getText();
      
      expect(saveText).toBe('Save Host');
      expect(cancelText).toBe('Cancel');
    });
  });

  describe('Host List', () => {
    it('should have a host list container', async () => {
      const hostList = await $('#host-list');
      await expect(hostList).toBeExisting();
    });
  });

  describe('Modals', () => {
    it('should have AD scan modal', async () => {
      const modal = await $('#scan-modal');
      await expect(modal).toBeExisting();
    });

    it('should have delete confirmation modal', async () => {
      const modal = await $('#delete-modal');
      await expect(modal).toBeExisting();
    });

    it('should have generic confirmation modal', async () => {
      const modal = await $('#confirm-modal');
      await expect(modal).toBeExisting();
    });

    it('should have service browser modal', async () => {
      const modal = await $('#service-browser-modal');
      await expect(modal).toBeExisting();
    });
  });

  describe('Scan AD Modal', () => {
    // Note: Modal interaction tests (open/close via button click) are skipped
    // because the native <dialog> showModal() behavior requires full user
    // interaction context which WebDriver cannot reliably simulate.
    // The modal existence and structure tests below verify the modal is present.
    
    it('should have domain input in scan modal', async () => {
      const domainInput = await $('#scan-domain');
      await expect(domainInput).toBeExisting();
      
      const placeholder = await domainInput.getAttribute('placeholder');
      expect(placeholder).toContain('contoso.com');
    });

    it('should have DC input in scan modal', async () => {
      const dcInput = await $('#scan-dc');
      await expect(dcInput).toBeExisting();
      
      const placeholder = await dcInput.getAttribute('placeholder');
      expect(placeholder).toContain('dc01');
    });
    
    it('should have scan and cancel buttons', async () => {
      const scanRunBtn = await $('#scan-run');
      const cancelBtn = await $('#scan-cancel');
      
      await expect(scanRunBtn).toBeExisting();
      await expect(cancelBtn).toBeExisting();
    });
  });

  describe('Form Validation', () => {
    beforeEach(async () => {
      await dismissBlockingModals();
    });
    
    it('should require host name to submit form', async () => {
      // Ensure form is visible and interactable
      const hostNameInput = await $('#host-name');
      await expect(hostNameInput).toBeExisting();
      await browser.pause(200);
      
      // Scroll to the input to ensure visibility
      await hostNameInput.scrollIntoView();
      await browser.pause(200);
      
      // Clear any existing value
      await hostNameInput.clearValue();
      
      // Try to submit
      const saveBtn = await $('#host-form button[type="submit"]');
      await saveBtn.scrollIntoView();
      await browser.pause(200);
      await saveBtn.click();
      await browser.pause(300);
      
      // Form should not submit - we should still be on hosts page
      // and no banner error should appear (just HTML5 validation)
      const url = await browser.getUrl();
      expect(url).toContain('hosts');
    });
  });

  describe('Navigation', () => {
    beforeEach(async () => {
      await dismissBlockingModals();
    });
    
    it('should navigate back to dashboard when clicking Back button', async () => {
      // Ensure we're on hosts page first
      await ensureOnHostsPage();
      await dismissBlockingModals();
      
      const backBtn = await $('#back-dashboard');
      await expect(backBtn).toBeClickable();
      await backBtn.click();
      
      await browser.waitUntil(
        async () => (await browser.getUrl()).includes('dashboard'),
        { timeout: 10000, timeoutMsg: 'Failed to navigate back to dashboard' }
      );
      
      const url = await browser.getUrl();
      expect(url).toContain('dashboard');
    });
  });
});
