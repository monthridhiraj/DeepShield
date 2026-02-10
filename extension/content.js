/**
 * DeepShield Content Script
 * Injects warning/block overlays and monitors page for threats
 */

// ============================================================================
// STATE
// ============================================================================
let overlayVisible = false;
let currentVerdict = null;

// ============================================================================
// OVERLAY CREATION
// ============================================================================

/**
 * Create and inject the warning/block overlay
 */
function createOverlay(verdict, type = 'block') {
  // Remove existing overlay if any
  removeOverlay();

  const overlay = document.createElement('div');
  overlay.id = 'deepshield-overlay';
  overlay.setAttribute('data-type', type);

  const isBlock = type === 'block';
  const color = isBlock ? '#EF4444' : '#F59E0B';
  const icon = isBlock ? '🚫' : '⚠️';
  const title = isBlock ? 'Phishing Site Blocked' : 'Suspicious Site Detected';
  const subtitle = isBlock
    ? 'DeepShield has blocked this page for your protection'
    : 'This site shows signs of being a phishing attempt';

  overlay.innerHTML = `
    <div class="deepshield-container">
      <div class="deepshield-icon">${icon}</div>
      <div class="deepshield-shield">🛡️</div>
      <h1 class="deepshield-title">${title}</h1>
      <p class="deepshield-subtitle">${subtitle}</p>
      
      <div class="deepshield-details">
        <div class="deepshield-url">
          <span class="label">URL:</span>
          <span class="value">${escapeHtml(window.location.href)}</span>
        </div>
        <div class="deepshield-confidence">
          <span class="label">Threat Confidence:</span>
          <span class="value">${(verdict.confidence * 100).toFixed(1)}%</span>
        </div>
        ${verdict.message ? `
        <div class="deepshield-reason">
          <span class="label">Reason:</span>
          <span class="value">${escapeHtml(verdict.message)}</span>
        </div>
        ` : ''}
      </div>
      
      <div class="deepshield-actions">
        <button class="deepshield-btn deepshield-btn-primary" id="deepshield-go-back">
          ← Go Back to Safety
        </button>
        ${!isBlock ? `
        <button class="deepshield-btn deepshield-btn-secondary" id="deepshield-proceed">
          Proceed Anyway (Not Recommended)
        </button>
        ` : ''}
        <button class="deepshield-btn deepshield-btn-tertiary" id="deepshield-report">
          Report False Positive
        </button>
      </div>
      
      <div class="deepshield-footer">
        <span>Protected by DeepShield AI</span>
        <span class="deepshield-version">v1.0.0</span>
      </div>
    </div>
  `;

  // Inject styles if not already present
  if (!document.getElementById('deepshield-styles')) {
    const styles = document.createElement('style');
    styles.id = 'deepshield-styles';
    styles.textContent = getOverlayStyles(color);
    document.head.appendChild(styles);
  }

  document.body.appendChild(overlay);
  overlayVisible = true;

  // Event listeners
  document.getElementById('deepshield-go-back')?.addEventListener('click', () => {
    window.history.back();
    setTimeout(() => {
      if (window.location.href === document.referrer || !document.referrer) {
        window.location.href = 'https://www.google.com';
      }
    }, 100);
  });

  document.getElementById('deepshield-proceed')?.addEventListener('click', () => {
    if (confirm('⚠️ Are you sure you want to proceed? This site may steal your personal information.')) {
      removeOverlay();
      chrome.runtime.sendMessage({
        type: 'WHITELIST_URL',
        url: window.location.href,
      });
    }
  });

  document.getElementById('deepshield-report')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      type: 'REPORT_FALSE_POSITIVE',
      url: window.location.href,
      verdict,
    });
    alert('Thank you! Your report has been submitted for review.');
  });

  // Prevent interaction with underlying page for blocks
  if (isBlock) {
    document.body.style.overflow = 'hidden';
  }
}

/**
 * Remove the overlay
 */
function removeOverlay() {
  const overlay = document.getElementById('deepshield-overlay');
  if (overlay) {
    overlay.remove();
    document.body.style.overflow = '';
    overlayVisible = false;
  }
}

/**
 * Escape HTML entities
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Generate overlay CSS styles
 */
function getOverlayStyles(accentColor) {
  return `
    #deepshield-overlay {
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      bottom: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif !important;
      animation: deepshield-fade-in 0.3s ease-out !important;
    }
    
    @keyframes deepshield-fade-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    @keyframes deepshield-pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.1); opacity: 0.8; }
    }
    
    @keyframes deepshield-shake {
      0%, 100% { transform: translateX(0); }
      10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
      20%, 40%, 60%, 80% { transform: translateX(5px); }
    }
    
    .deepshield-container {
      background: rgba(255, 255, 255, 0.05) !important;
      backdrop-filter: blur(20px) !important;
      -webkit-backdrop-filter: blur(20px) !important;
      border: 1px solid rgba(255, 255, 255, 0.1) !important;
      border-radius: 24px !important;
      padding: 48px !important;
      max-width: 600px !important;
      width: 90% !important;
      text-align: center !important;
      box-shadow: 
        0 25px 50px -12px rgba(0, 0, 0, 0.5),
        0 0 0 1px rgba(255, 255, 255, 0.05),
        inset 0 1px 0 rgba(255, 255, 255, 0.1) !important;
    }
    
    .deepshield-icon {
      font-size: 80px !important;
      margin-bottom: 8px !important;
      animation: deepshield-shake 0.5s ease-in-out !important;
    }
    
    .deepshield-shield {
      font-size: 48px !important;
      margin-bottom: 24px !important;
      animation: deepshield-pulse 2s ease-in-out infinite !important;
    }
    
    .deepshield-title {
      font-size: 32px !important;
      font-weight: 700 !important;
      color: ${accentColor} !important;
      margin: 0 0 12px 0 !important;
      text-shadow: 0 2px 10px ${accentColor}40 !important;
    }
    
    .deepshield-subtitle {
      font-size: 16px !important;
      color: rgba(255, 255, 255, 0.7) !important;
      margin: 0 0 32px 0 !important;
      line-height: 1.5 !important;
    }
    
    .deepshield-details {
      background: rgba(0, 0, 0, 0.3) !important;
      border-radius: 12px !important;
      padding: 20px !important;
      margin-bottom: 32px !important;
      text-align: left !important;
    }
    
    .deepshield-details > div {
      display: flex !important;
      justify-content: space-between !important;
      padding: 8px 0 !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
    }
    
    .deepshield-details > div:last-child {
      border-bottom: none !important;
    }
    
    .deepshield-details .label {
      color: rgba(255, 255, 255, 0.5) !important;
      font-size: 13px !important;
    }
    
    .deepshield-details .value {
      color: white !important;
      font-size: 13px !important;
      font-weight: 500 !important;
      max-width: 300px !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
      white-space: nowrap !important;
    }
    
    .deepshield-details .deepshield-confidence .value {
      color: ${accentColor} !important;
      font-weight: 700 !important;
    }
    
    .deepshield-actions {
      display: flex !important;
      flex-direction: column !important;
      gap: 12px !important;
    }
    
    .deepshield-btn {
      padding: 14px 28px !important;
      border-radius: 12px !important;
      font-size: 15px !important;
      font-weight: 600 !important;
      cursor: pointer !important;
      transition: all 0.2s ease !important;
      border: none !important;
    }
    
    .deepshield-btn-primary {
      background: linear-gradient(135deg, #10B981, #059669) !important;
      color: white !important;
      box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4) !important;
    }
    
    .deepshield-btn-primary:hover {
      transform: translateY(-2px) !important;
      box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5) !important;
    }
    
    .deepshield-btn-secondary {
      background: rgba(255, 255, 255, 0.1) !important;
      color: rgba(255, 255, 255, 0.7) !important;
      border: 1px solid rgba(255, 255, 255, 0.2) !important;
    }
    
    .deepshield-btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15) !important;
      color: white !important;
    }
    
    .deepshield-btn-tertiary {
      background: transparent !important;
      color: rgba(255, 255, 255, 0.5) !important;
      font-size: 13px !important;
      padding: 10px !important;
    }
    
    .deepshield-btn-tertiary:hover {
      color: rgba(255, 255, 255, 0.8) !important;
    }
    
    .deepshield-footer {
      margin-top: 32px !important;
      display: flex !important;
      justify-content: center !important;
      align-items: center !important;
      gap: 12px !important;
      color: rgba(255, 255, 255, 0.4) !important;
      font-size: 12px !important;
    }
    
    .deepshield-version {
      background: rgba(255, 255, 255, 0.1) !important;
      padding: 4px 8px !important;
      border-radius: 4px !important;
    }
  `;
}

// ============================================================================
// SAFE BADGE (Optional - shows green checkmark on safe sites)
// ============================================================================

function showSafeBadge() {
  if (document.getElementById('deepshield-safe-badge')) return;

  const badge = document.createElement('div');
  badge.id = 'deepshield-safe-badge';
  badge.innerHTML = `
    <span class="icon">🛡️</span>
    <span class="text">Protected</span>
  `;

  const style = document.createElement('style');
  style.id = 'deepshield-safe-badge-styles';
  style.textContent = `
    #deepshield-safe-badge {
      position: fixed !important;
      bottom: 20px !important;
      right: 20px !important;
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.9), rgba(5, 150, 105, 0.9)) !important;
      backdrop-filter: blur(10px) !important;
      color: white !important;
      padding: 8px 16px !important;
      border-radius: 20px !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      font-size: 13px !important;
      font-weight: 600 !important;
      display: flex !important;
      align-items: center !important;
      gap: 6px !important;
      z-index: 999999 !important;
      box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3) !important;
      animation: deepshield-badge-in 0.3s ease-out !important;
      cursor: pointer !important;
      transition: all 0.2s ease !important;
    }
    
    #deepshield-safe-badge:hover {
      transform: scale(1.05) !important;
      box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4) !important;
    }
    
    @keyframes deepshield-badge-in {
      from { 
        opacity: 0; 
        transform: translateY(20px); 
      }
      to { 
        opacity: 1; 
        transform: translateY(0); 
      }
    }
    
    #deepshield-safe-badge .icon {
      font-size: 16px !important;
    }
  `;

  document.head.appendChild(style);
  document.body.appendChild(badge);

  // Auto-hide after 3 seconds
  setTimeout(() => {
    badge.style.opacity = '0';
    badge.style.transform = 'translateY(20px)';
    setTimeout(() => badge.remove(), 300);
  }, 3000);

  badge.addEventListener('click', () => {
    badge.remove();
  });
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PHISHING_DETECTED') {
    currentVerdict = message.verdict;
    handleVerdict(message.verdict);
    sendResponse({ received: true });
  }

  if (message.type === 'PHISHING_WARNING') {
    currentVerdict = message.verdict;
    handleVerdict(message.verdict);
    sendResponse({ received: true });
  }

  if (message.type === 'SAFE_SITE') {
    currentVerdict = message.verdict;
    handleVerdict(message.verdict);
    sendResponse({ received: true });
  }

  if (message.type === 'GET_PAGE_INFO') {
    sendResponse({
      url: window.location.href,
      title: document.title,
      hasOverlay: overlayVisible,
    });
  }

  return true;
});

// ============================================================================
// INITIALIZATION
// ============================================================================


// ============================================================================
// STRICT BLOCKING INIT
// ============================================================================

// 1. Show scanning overlay IMMEDIATELY
createScanningOverlay();

// 2. Check for verdict
chrome.runtime.sendMessage({ type: 'GET_CURRENT_VERDICT' }, (response) => {
  if (response) {
    handleVerdict(response);
  }
});

function handleVerdict(verdict) {
  if (verdict.action === 'block') {
    createOverlay(verdict, 'block');
  } else if (verdict.action === 'warn') {
    createOverlay(verdict, 'warn');
  } else {
    // Safe or unknown - remove scanning overlay
    removeOverlay();
    if (verdict.action === 'allow' && !verdict.isPhishing) {
      // Optional: Show safe badge
      // showSafeBadge();
    }
  }
}

/**
 * Create initial scanning overlay
 */
function createScanningOverlay() {
  if (document.getElementById('deepshield-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'deepshield-overlay';
  overlay.setAttribute('data-type', 'scanning');

  overlay.innerHTML = `
    <div class="deepshield-container">
      <div class="deepshield-shield">🛡️</div>
      <h1 class="deepshield-title" style="color: #60A5FA !important;">Analyzing...</h1>
      <p class="deepshield-subtitle">DeepShield is verifying this site's safety.</p>
      
      <div class="deepshield-scan-animation">
        <div class="scan-ring"></div>
        <div class="scan-ring"></div>
        <div class="scan-ring"></div>
      </div>
      
      <div class="deepshield-footer">
        <span>Protected by DeepShield AI</span>
      </div>
    </div>
    `;

  // Inject styles
  if (!document.getElementById('deepshield-styles')) {
    const styles = document.createElement('style');
    styles.id = 'deepshield-styles';
    styles.textContent = getOverlayStyles('#60A5FA') + `
            .deepshield-scan-animation {
                display: flex;
                justify-content: center;
                gap: 8px;
                margin: 24px 0;
            }
            .scan-ring {
                width: 12px;
                height: 12px;
                background: #60A5FA;
                border-radius: 50%;
                animation: deepshield-bounce 1.4s infinite ease-in-out both;
            }
            .scan-ring:nth-child(1) { animation-delay: -0.32s; }
            .scan-ring:nth-child(2) { animation-delay: -0.16s; }
            
            @keyframes deepshield-bounce {
                0%, 80%, 100% { transform: scale(0); }
                40% { transform: scale(1); }
            }
        `;
    document.head.appendChild(styles);
  }

  document.body.appendChild(overlay);
  document.body.style.overflow = 'hidden'; // Prevent scrolling while scanning
}

