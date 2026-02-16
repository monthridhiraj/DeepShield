/**
 * DeepShield Background Service Worker
 * Handles URL interception, API communication, and verdict caching
 */

// ============================================================================
// CONFIGURATION
// ============================================================================
const CONFIG = {
  API_BASE_URL: 'http://localhost:8000',
  CACHE_TTL: 5 * 60 * 1000, // 5 minutes
  REQUEST_TIMEOUT: 3000, // 3 seconds
  MAX_CACHE_SIZE: 1000,
  LATENCY_BUDGET: 150, // ms
};

// Trusted domains whitelist for offline mode
const TRUSTED_DOMAINS = new Set([
  'google.com', 'www.google.com', 'accounts.google.com',
  'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
  'github.com', 'www.github.com',
  'amazon.com', 'www.amazon.com',
  'facebook.com', 'www.facebook.com',
  'twitter.com', 'www.twitter.com', 'x.com',
  'linkedin.com', 'www.linkedin.com',
  'apple.com', 'www.apple.com',
  'youtube.com', 'www.youtube.com',
  'netflix.com', 'www.netflix.com',
  'wikipedia.org', 'en.wikipedia.org',
  'reddit.com', 'www.reddit.com',
  'stackoverflow.com', 'www.stackoverflow.com',
  'paypal.com', 'www.paypal.com',
  'chase.com', 'www.chase.com',
  'bankofamerica.com', 'www.bankofamerica.com',
]);

// ============================================================================
// STATE MANAGEMENT
// ============================================================================
const urlCache = new Map();
const scanStats = {
  totalScanned: 0,
  blocked: 0,
  warned: 0,
  safe: 0,
  lastScan: null,
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Extract domain from URL
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Check if URL is internal/extension URL
 */
function isInternalUrl(url) {
  return url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('moz-extension://') ||
    url.startsWith('about:') ||
    url.startsWith('edge://') ||
    url.startsWith('file://');
}

/**
 * Get cached verdict if available and not expired
 */
function getCachedVerdict(url) {
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_TTL) {
    return cached;
  }
  urlCache.delete(url);
  return null;
}

/**
 * Cache verdict with timestamp
 */
function cacheVerdict(url, verdict) {
  // Enforce max cache size
  if (urlCache.size >= CONFIG.MAX_CACHE_SIZE) {
    const firstKey = urlCache.keys().next().value;
    urlCache.delete(firstKey);
  }

  urlCache.set(url, {
    ...verdict,
    timestamp: Date.now(),
  });
}

/**
 * Check if API is reachable
 */
async function checkApiHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`${CONFIG.API_BASE_URL}/health`, {
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    return response.ok;
  } catch {
    return false;
  }
}

// ============================================================================
// CORE PREDICTION LOGIC
// ============================================================================

/**
 * Analyze URL using DeepShield API
 */
async function analyzeUrl(url) {
  const startTime = performance.now();

  // Check cache first
  const cached = getCachedVerdict(url);
  if (cached) {
    console.log(`[DeepShield] Cache hit for: ${url}`);
    return { ...cached, fromCache: true };
  }

  // Check if trusted domain (fast path)
  const domain = extractDomain(url);
  if (domain && TRUSTED_DOMAINS.has(domain)) {
    const verdict = {
      verdict: 'safe',
      confidence: 1.0,
      message: 'Trusted domain',
      isPhishing: false,
    };
    cacheVerdict(url, verdict);
    return verdict;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    const response = await fetch(`${CONFIG.API_BASE_URL}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    const latency = performance.now() - startTime;

    // Parse API response
    const verdict = {
      verdict: data.verdict?.toLowerCase() || 'unknown',
      confidence: data.confidence || 0,
      isPhishing: data.final_prediction === 1 || data.verdict === 'Phishing',
      message: data.recommendation || '',
      mlModels: data.ml_models || {},
      dlModels: data.dl_models || {},
      latency: Math.round(latency),
    };

    // Determine action based on confidence
    if (verdict.isPhishing) {
      if (verdict.confidence >= 0.8) {
        verdict.action = 'block';
      } else if (verdict.confidence >= 0.5) {
        verdict.action = 'warn';
      } else {
        verdict.action = 'allow';
      }
    } else {
      verdict.action = 'allow';
    }

    cacheVerdict(url, verdict);

    console.log(`[DeepShield] Analyzed ${url} in ${latency.toFixed(0)}ms:`, verdict);
    return verdict;

  } catch (error) {
    console.error(`[DeepShield] Analysis failed for ${url}:`, error);

    // Offline fallback: check trusted domains only
    if (domain && TRUSTED_DOMAINS.has(domain)) {
      return {
        verdict: 'safe',
        confidence: 0.8,
        message: 'Offline mode - trusted domain',
        isPhishing: false,
        action: 'allow',
        offline: true,
      };
    }

    // Unknown - allow with warning
    return {
      verdict: 'unknown',
      confidence: 0,
      message: 'Unable to analyze - API unavailable',
      isPhishing: false,
      action: 'allow',
      error: error.message,
      offline: true,
    };
  }
}

// ============================================================================
// NAVIGATION INTERCEPTION
// ============================================================================

/**
 * Handle navigation event
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only handle main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip internal URLs
  if (isInternalUrl(url)) return;

  console.log(`[DeepShield] Checking URL: ${url}`);

  try {
    const verdict = await analyzeUrl(url);

    // Update stats
    scanStats.totalScanned++;
    scanStats.lastScan = { url, verdict, timestamp: Date.now() };

    if (verdict.action === 'block') {
      scanStats.blocked++;

      // Redirect to block page
      const blockPageUrl = chrome.runtime.getURL('block.html') + '?url=' + encodeURIComponent(url);
      chrome.tabs.update(details.tabId, { url: blockPageUrl });

      // Update badge
      updateBadge(details.tabId, 'block');

      // Optional: notification
      /*
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: 'DeepShield Alert',
        message: `Blocked phishing attempt: ${extractDomain(url)}`,
        priority: 2,
      });
      */

    } else if (verdict.action === 'warn') {
      scanStats.warned++;

      chrome.tabs.sendMessage(details.tabId, {
        type: 'PHISHING_WARNING',
        verdict,
        url,
      }).catch(() => { });

      updateBadge(details.tabId, 'warn');

    } else {
      scanStats.safe++;
      // Send message to content script to unlock the page
      chrome.tabs.sendMessage(details.tabId, {
        type: 'SAFE_SITE',
        verdict,
        url,
      }).catch(() => { });

      updateBadge(details.tabId, 'safe');
    }

    // Store verdict for popup
    chrome.storage.session.set({
      [`verdict_${details.tabId}`]: verdict,
      lastVerdict: verdict,
      scanStats,
    });

  } catch (error) {
    console.error('[DeepShield] Navigation handler error:', error);
  }
});

// ============================================================================
// BADGE MANAGEMENT
// ============================================================================

/**
 * Update extension badge based on verdict
 */
function updateBadge(tabId, status) {
  const badges = {
    block: { color: '#EF4444', text: '⚠' },
    warn: { color: '#F59E0B', text: '!' },
    safe: { color: '#10B981', text: '✓' },
    unknown: { color: '#6B7280', text: '?' },
  };

  const badge = badges[status] || badges.unknown;

  chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId });
  chrome.action.setBadgeText({ text: badge.text, tabId });
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_VERDICT') {
    analyzeUrl(message.url).then(sendResponse);
    return true; // Keep channel open for async response
  }

  if (message.type === 'GET_STATS') {
    sendResponse(scanStats);
    return true;
  }

  if (message.type === 'GET_CURRENT_VERDICT') {
    chrome.storage.session.get(`verdict_${sender.tab?.id}`).then((result) => {
      sendResponse(result[`verdict_${sender.tab?.id}`] || null);
    });
    return true;
  }

  if (message.type === 'CHECK_API_HEALTH') {
    checkApiHealth().then(sendResponse);
    return true;
  }

  if (message.type === 'WHITELIST_URL') {
    const domain = extractDomain(message.url);
    if (domain) {
      TRUSTED_DOMAINS.add(domain);
      // Clear cache for this URL
      urlCache.delete(message.url);
      sendResponse({ success: true, domain });
    } else {
      sendResponse({ success: false, error: 'Invalid URL' });
    }
    return true;
  }

  if (message.type === 'REPORT_SAFE') {
    const url = message.url;
    const domain = extractDomain(url);

    // Call the feedback API from background (no CSP issues here)
    fetch(`${CONFIG.API_BASE_URL}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, verdict: 'safe' })
    })
      .then(response => {
        if (response.ok) {
          // Also whitelist the domain locally
          if (domain) {
            TRUSTED_DOMAINS.add(domain);
            urlCache.delete(url);
          }
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'API error' });
        }
      })
      .catch(error => {
        console.error('[DeepShield] Feedback API error:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep channel open for async response
  }

  if (message.type === 'CLEAR_CACHE') {
    urlCache.clear();
    sendResponse({ success: true });
    return true;
  }
});

// ============================================================================
// INITIALIZATION
// ============================================================================

console.log('[DeepShield] Background service worker initialized');

// Check API health on startup
checkApiHealth().then((healthy) => {
  console.log(`[DeepShield] API status: ${healthy ? 'Online' : 'Offline'}`);
  chrome.storage.session.set({ apiHealthy: healthy });
});

// Periodic health check
setInterval(async () => {
  const healthy = await checkApiHealth();
  chrome.storage.session.set({ apiHealthy: healthy });
}, 30000);
