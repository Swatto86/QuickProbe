/**
 * QuickProbe E2E Test: Dashboard
 *
 * Tests the dashboard page functionality including:
 * - Header and navigation elements
 * - Search functionality
 * - Stats display
 * - View switching (Cards/Groups)
 * - Server grid
 */

describe('QuickProbe Dashboard', () => {
  /**
   * Navigate to dashboard
   */
  async function ensureOnDashboard() {
    const url = await browser.getUrl();
    if (!url.includes('dashboard')) {
      // Tauri 2.x uses http:// instead of https://
      await browser.url('http://tauri.localhost/dashboard-all.html');
      await browser.pause(2000);
    }
    
    // Wait for dashboard to load
    await browser.waitUntil(
      async () => {
        const grid = await $('#servers-grid');
        const empty = await $('#empty-state');
        return (await grid.isExisting()) || (await empty.isExisting());
      },
      { timeout: 15000, timeoutMsg: 'Dashboard did not load within 15 seconds' }
    );
  }

  before(async () => {
    await ensureOnDashboard();
  });

  describe('Header Elements', () => {
    it('should display the QuickProbe header title', async () => {
      const title = await $('h1.text-primary');
      await expect(title).toBeExisting();
      const titleText = await title.getText();
      expect(titleText).toBe('QuickProbe');
    });

    it('should display view toggle buttons (Cards/Groups)', async () => {
      const cardsBtn = await $('button[data-view="cards"]');
      const groupsBtn = await $('button[data-view="groups"]');
      
      await expect(cardsBtn).toBeExisting();
      await expect(groupsBtn).toBeExisting();
      
      const cardsBtnText = await cardsBtn.getText();
      const groupsBtnText = await groupsBtn.getText();
      
      expect(cardsBtnText).toBe('Cards');
      expect(groupsBtnText).toBe('Groups');
    });

    it('should display the Reorder button', async () => {
      const reorderBtn = await $('#reorder-btn');
      await expect(reorderBtn).toBeExisting();
      
      const btnText = await reorderBtn.getText();
      expect(btnText).toContain('Reorder');
    });

    it('should display the Edit Hosts button', async () => {
      const editHostsBtn = await $('#edit-hosts-btn');
      await expect(editHostsBtn).toBeExisting();
      await expect(editHostsBtn).toBeClickable();
      
      const btnText = await editHostsBtn.getText();
      expect(btnText).toContain('Edit Hosts');
    });

    it('should display the Refresh Visible button', async () => {
      const refreshBtn = await $('#refresh-visible-btn');
      await expect(refreshBtn).toBeExisting();
      await expect(refreshBtn).toBeClickable();
      
      const btnText = await refreshBtn.getText();
      expect(btnText).toContain('Refresh');
    });

    it('should display the Back to Login button', async () => {
      const backBtn = await $('#back-to-login-btn');
      await expect(backBtn).toBeExisting();
      await expect(backBtn).toBeClickable();
      
      const btnText = await backBtn.getText();
      expect(btnText).toContain('Back to Login');
    });
  });

  describe('Search Section', () => {
    it('should have a search input field', async () => {
      const searchInput = await $('#server-search');
      await expect(searchInput).toBeExisting();
      await expect(searchInput).toBeDisplayed();
      
      const placeholder = await searchInput.getAttribute('placeholder');
      expect(placeholder).toContain('Search');
    });

    it('should have a clear search button', async () => {
      const clearBtn = await $('#clear-search-btn');
      await expect(clearBtn).toBeExisting();
      
      const btnText = await clearBtn.getText();
      expect(btnText).toBe('Clear');
    });

    it('should have a search meta text element', async () => {
      const searchMeta = await $('#search-meta');
      await expect(searchMeta).toBeExisting();
      
      const metaText = await searchMeta.getText();
      expect(metaText).toContain('servers');
    });

    it('should accept search input', async () => {
      const searchInput = await $('#server-search');
      await searchInput.click();
      await searchInput.setValue('test-server');
      await browser.pause(300);
      
      const value = await searchInput.getValue();
      expect(value).toBe('test-server');
      
      // Clear the search after test
      const clearBtn = await $('#clear-search-btn');
      await clearBtn.click();
      await browser.pause(200);
    });
  });

  describe('Summary Stats Section', () => {
    it('should have a summary stats container', async () => {
      const statsContainer = await $('#summary-stats');
      await expect(statsContainer).toBeExisting();
    });

    it('should display Total Servers stat', async () => {
      const totalStat = await $('#stat-total');
      await expect(totalStat).toBeExisting();
      
      const value = await totalStat.getText();
      // Should be a number (including 0)
      expect(parseInt(value, 10)).toBeGreaterThanOrEqual(0);
    });

    it('should display Online stat', async () => {
      const onlineStat = await $('#stat-online');
      await expect(onlineStat).toBeExisting();
    });

    it('should display Offline stat', async () => {
      const offlineStat = await $('#stat-offline');
      await expect(offlineStat).toBeExisting();
    });

    it('should have clickable stat cards for filtering', async () => {
      const allFilter = await $('[data-filter="all"]');
      const onlineFilter = await $('[data-filter="online"]');
      const offlineFilter = await $('[data-filter="offline"]');
      
      await expect(allFilter).toBeExisting();
      await expect(onlineFilter).toBeExisting();
      await expect(offlineFilter).toBeExisting();
      
      // Verify they have role="button" for accessibility
      const allRole = await allFilter.getAttribute('role');
      expect(allRole).toBe('button');
    });
  });

  describe('Content Area', () => {
    it('should have a servers grid container', async () => {
      const serversGrid = await $('#servers-grid');
      await expect(serversGrid).toBeExisting();
    });

    it('should have an empty state container', async () => {
      const emptyState = await $('#empty-state');
      await expect(emptyState).toBeExisting();
    });

    it('should have a loading indicator', async () => {
      const loading = await $('#loading');
      await expect(loading).toBeExisting();
      
      // Loading should be hidden when not refreshing
      const classList = await loading.getAttribute('class');
      expect(classList).toContain('hidden');
    });
  });

  describe('Modals', () => {
    it('should have RDP credential modal', async () => {
      const modal = await $('#rdp-credential-modal');
      await expect(modal).toBeExisting();
    });

    it('should have notes modal', async () => {
      const modal = await $('#notes-modal');
      await expect(modal).toBeExisting();
    });

    it('should have edit host modal', async () => {
      const modal = await $('#edit-host-modal');
      await expect(modal).toBeExisting();
    });

    it('should have error modal', async () => {
      const modal = await $('#error-modal');
      await expect(modal).toBeExisting();
    });
  });

  describe('View Toggle Behavior', () => {
    it('should toggle view when clicking Cards/Groups buttons', async () => {
      const cardsBtn = await $('button[data-view="cards"]');
      const groupsBtn = await $('button[data-view="groups"]');
      
      // Click Groups
      await groupsBtn.click();
      await browser.pause(300);
      
      // Click back to Cards
      await cardsBtn.click();
      await browser.pause(300);
      
      // Both buttons should still exist and be clickable
      await expect(cardsBtn).toBeClickable();
      await expect(groupsBtn).toBeClickable();
    });
  });

  describe('Notification Area', () => {
    it('should have a notification stack container', async () => {
      const notificationStack = await $('#notification-stack');
      await expect(notificationStack).toBeExisting();
      
      const classList = await notificationStack.getAttribute('class');
      expect(classList).toContain('toast');
    });
  });
});
