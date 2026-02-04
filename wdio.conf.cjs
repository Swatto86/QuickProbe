/**
 * WebdriverIO Configuration for QuickProbe E2E Testing
 *
 * Strategy: Start the Tauri app with WebView2 remote debugging enabled,
 * then connect msedgedriver to it via debuggerAddress.
 *
 * IMPORTANT: The QuickProbe window may be hidden in the system tray when
 * credentials exist. Tests use the E2E test mode flag to ensure:
 * 1. The window is always shown
 * 2. Auto-login countdown is disabled
 * 
 * Prerequisites:
 * 1. Build the app: npm run tauri build
 * 2. Install msedgedriver matching your WebView2 version
 * 3. Place msedgedriver.exe in project root or add to PATH
 *
 * Usage:
 *   npm run test:e2e                           # Run all E2E tests
 *   npm run test:e2e:spec e2e/login.spec.js    # Run specific test file
 */

const { spawn, spawnSync } = require('child_process');
const path = require('path');

// Remote debugging port for WebView2
const DEBUG_PORT = 9222;

// msedgedriver port
const DRIVER_PORT = 4444;

/**
 * Determine the application binary path based on platform
 */
function getAppBinaryPath() {
  const platform = process.platform;
  const basePath = path.resolve(__dirname, 'src-tauri', 'target', 'release');

  if (platform === 'win32') {
    return path.join(basePath, 'QuickProbe.exe');
  } else if (platform === 'darwin') {
    return path.join(basePath, 'bundle', 'macos', 'QuickProbe.app', 'Contents', 'MacOS', 'QuickProbe');
  } else {
    return path.join(basePath, 'quickprobe');
  }
}

/**
 * Kill processes using specific ports (Windows)
 */
function killPortProcesses(ports) {
  if (process.platform === 'win32') {
    ports.forEach(port => {
      try {
        spawnSync('cmd', ['/c', `for /f "tokens=5" %a in ('netstat -ano ^| findstr :${port}') do taskkill /F /PID %a`], {
          shell: true,
          stdio: 'ignore'
        });
      } catch (e) {
        // Ignore errors - port might not be in use
      }
    });
  }
}

let edgeDriver = null;
let tauriApp = null;

exports.config = {
  //
  // ====================
  // Runner Configuration
  // ====================
  hostname: '127.0.0.1',
  port: DRIVER_PORT,
  runner: 'local',
  // Force single worker to prevent concurrent session issues
  maxInstancesPerCapability: 1,

  //
  // ==================
  // Test Configuration
  // ==================
  // Run one spec file at a time to avoid connection issues
  specs: ['./e2e/**/*.spec.js'],
  exclude: [],
  maxInstances: 1,
  // Run specs sequentially, not in parallel workers
  specFileRetries: 1,
  specFileRetriesDeferred: true,

  //
  // ============
  // Capabilities
  // ============
  // Connect to already-running app via debuggerAddress
  capabilities: [{
    maxInstances: 1,
    browserName: 'webview2',
    'ms:edgeOptions': {
      debuggerAddress: `localhost:${DEBUG_PORT}`,
    },
  }],

  //
  // ===================
  // Test Configurations
  // ===================
  logLevel: 'warn',
  bail: 0,
  baseUrl: '',
  waitforTimeout: 15000,
  connectionRetryTimeout: 120000,
  connectionRetryCount: 3,

  //
  // ==============
  // Test Framework
  // ==============
  framework: 'mocha',
  mochaOpts: {
    ui: 'bdd',
    timeout: 60000,
    retries: 1
  },

  //
  // ==========
  // Reporters
  // ==========
  reporters: ['spec'],

  //
  // =====
  // Hooks
  // =====

  /**
   * Gets executed once before all workers get launched.
   * Start the Tauri app and msedgedriver.
   */
  onPrepare: async function () {
    const appPath = getAppBinaryPath();
    console.log(`\n[E2E Setup] App path: ${appPath}`);

    // Kill any existing processes on our ports
    console.log('[E2E Setup] Cleaning up existing processes...');
    killPortProcesses([DRIVER_PORT, DEBUG_PORT]);

    // Wait for ports to be released
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Start Tauri app with WebView2 remote debugging
    console.log('[E2E Setup] Starting Tauri application...');
    tauriApp = spawn(appPath, [], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
      env: {
        ...process.env,
        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${DEBUG_PORT}`,
      },
    });

    tauriApp.stdout.on('data', (data) => {
      if (process.env.DEBUG) {
        console.log(`[App stdout] ${data}`);
      }
    });

    tauriApp.stderr.on('data', (data) => {
      if (process.env.DEBUG) {
        console.error(`[App stderr] ${data}`);
      }
    });

    tauriApp.on('error', (err) => {
      console.error('[E2E Setup] Failed to start Tauri app:', err.message);
    });

    // Wait for app to initialize
    console.log('[E2E Setup] Waiting for app to start (5s)...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Start msedgedriver
    console.log('[E2E Setup] Starting msedgedriver...');
    // Look for msedgedriver in project root first, then PATH
    const localDriver = path.join(__dirname, process.platform === 'win32' ? 'msedgedriver.exe' : 'msedgedriver');
    const driverPath = require('fs').existsSync(localDriver) ? localDriver : (process.platform === 'win32' ? 'msedgedriver.exe' : 'msedgedriver');
    console.log(`[E2E Setup] Using driver: ${driverPath}`);
    edgeDriver = spawn(driverPath, [`--port=${DRIVER_PORT}`, '--verbose'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    edgeDriver.stdout.on('data', (data) => {
      if (process.env.DEBUG) {
        console.log(`[Driver stdout] ${data}`);
      }
    });

    edgeDriver.stderr.on('data', (data) => {
      if (process.env.DEBUG) {
        console.error(`[Driver stderr] ${data}`);
      }
    });

    edgeDriver.on('error', (err) => {
      console.error('[E2E Setup] Failed to start msedgedriver:', err.message);
      console.error('Make sure msedgedriver is installed and in PATH.');
      console.error('Download from: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/');
    });

    // Wait for driver to be ready
    console.log('[E2E Setup] Waiting for driver to start (3s)...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Verify driver is responding
    try {
      const http = require('http');
      await new Promise((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${DRIVER_PORT}/status`, (res) => {
          console.log('[E2E Setup] Driver status check: HTTP', res.statusCode);
          resolve();
        });
        req.on('error', reject);
        req.setTimeout(5000, () => reject(new Error('Timeout')));
      });
    } catch (e) {
      console.error('[E2E Setup] Driver not responding:', e.message);
    }

    console.log('[E2E Setup] Setup complete. Running tests...\n');
  },

  /**
   * Gets executed after all workers got shut down and the process is about to exit.
   * Clean up the app and driver processes.
   */
  onComplete: async function () {
    console.log('\n[E2E Cleanup] Shutting down...');

    if (edgeDriver) {
      console.log('[E2E Cleanup] Stopping msedgedriver...');
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/F', '/T', '/PID', String(edgeDriver.pid)], { stdio: 'ignore' });
      } else {
        edgeDriver.kill('SIGTERM');
      }
    }

    if (tauriApp) {
      console.log('[E2E Cleanup] Stopping Tauri application...');
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/F', '/T', '/PID', String(tauriApp.pid)], { stdio: 'ignore' });
      } else {
        tauriApp.kill('SIGTERM');
      }
    }

    // Final cleanup of any orphaned processes
    killPortProcesses([DRIVER_PORT, DEBUG_PORT]);

    console.log('[E2E Cleanup] Cleanup complete.\n');
  },

  /**
   * Gets executed before test execution begins. At this point you can access
   * the browser and execute commands.
   * 
   * CRITICAL: This hook enables E2E test mode by:
   * 1. Sending Ctrl+Shift+R to show the window if hidden in system tray
   * 2. Setting localStorage flag that app.js checks
   * 3. Refreshing the page to re-initialize with E2E mode active
   */
  before: async function (capabilities, specs) {
    console.log('[E2E] Initializing test mode...');
    
    // First, send Ctrl+Shift+R to show the window if it's hidden
    // The window might be hidden in system tray - this global shortcut shows it
    if (process.platform === 'win32') {
      console.log('[E2E] Sending Ctrl+Shift+R to ensure window is visible...');
      spawnSync('powershell', [
        '-Command',
        `Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('^+r')`
      ], { stdio: 'ignore' });
    }
    
    // Wait for window to become visible
    await browser.pause(2000);
    
    // Set E2E test mode flag in localStorage
    // This flag is checked by app.js to:
    // - Skip auto-login countdown
    // - Force window to be visible
    await browser.execute(() => {
      localStorage.setItem('quickprobe_e2e_test', 'true');
      window.__QUICKPROBE_E2E_TEST__ = true;
    });
    
    // Refresh the page to re-run initialize() with E2E mode active
    await browser.refresh();
    
    // Wait for app to re-initialize with E2E mode
    await browser.pause(3000);
    
    console.log('[E2E] Test mode initialized successfully');
  },

  /**
   * Function to be executed before a test (in Mocha/Jasmine).
   */
  beforeTest: async function (test, context) {
    if (process.env.DEBUG) {
      console.log(`\n[Test] Running: ${test.title}`);
    }
  },

  /**
   * Function to be executed after a test (in Mocha/Jasmine).
   */
  afterTest: async function (test, context, { error, result, duration, passed, retries }) {
    if (!passed && process.env.DEBUG) {
      console.log(`[Test] FAILED: ${test.title}`);
      if (error) {
        console.log(`[Test] Error: ${error.message}`);
      }
    }
  },

  /**
   * Gets executed after all tests are done. Results object contains
   * test results summary.
   * 
   * CRITICAL: Clear E2E test mode flag to restore normal app behavior.
   * This ensures the app doesn't remain in test mode after tests complete.
   */
  after: async function (result, capabilities, specs) {
    console.log('[E2E] Cleaning up test mode...');
    
    try {
      // Clear E2E test mode flag from localStorage
      await browser.execute(() => {
        localStorage.removeItem('quickprobe_e2e_test');
        delete window.__QUICKPROBE_E2E_TEST__;
      });
      console.log('[E2E] E2E test flag cleared from localStorage');
    } catch (e) {
      console.warn('[E2E] Failed to clear E2E flag:', e.message);
    }
  },
};
