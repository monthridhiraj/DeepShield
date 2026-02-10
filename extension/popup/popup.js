/**
 * DeepShield Popup Script
 * Handles UI updates, API communication, and user interactions
 */

// ============================================================================
// DOM ELEMENTS
// ============================================================================
const elements = {
    connectionStatus: document.getElementById('connection-status'),
    currentStatus: document.getElementById('current-status'),
    currentUrl: document.getElementById('current-url'),

    // Stats
    statSafe: document.getElementById('stat-safe'),
    statWarned: document.getElementById('stat-warned'),
    statBlocked: document.getElementById('stat-blocked'),

    // Details
    verdictDetails: document.getElementById('verdict-details'),
    detailsGrid: document.getElementById('details-grid'),

    // Models
    modelsSection: document.getElementById('models-section'),
    modelsToggle: document.getElementById('models-toggle'),
    modelsContent: document.getElementById('models-content'),
    modelBars: document.getElementById('model-bars'),

    // Actions
    rescanBtn: document.getElementById('rescan-btn'),
    whitelistBtn: document.getElementById('whitelist-btn'),
    reportBtn: document.getElementById('report-btn'),

    // Footer
    settingsLink: document.getElementById('settings-link'),
    helpLink: document.getElementById('help-link'),
};

// ============================================================================
// STATE
// ============================================================================
let currentTabId = null;
let currentVerdict = null;

// ============================================================================
// INITIALIZATION
// ============================================================================

async function init() {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabId = tab?.id;

    if (tab?.url) {
        elements.currentUrl.textContent = truncateUrl(tab.url);
    }

    // Check API health
    checkApiHealth();

    // Load stats
    loadStats();

    // Get verdict for current tab
    await loadCurrentVerdict();

    // Setup event listeners
    setupEventListeners();
}

// ============================================================================
// API HEALTH CHECK
// ============================================================================

async function checkApiHealth() {
    try {
        const healthy = await chrome.runtime.sendMessage({ type: 'CHECK_API_HEALTH' });
        updateConnectionStatus(healthy);
    } catch (error) {
        console.error('Health check failed:', error);
        updateConnectionStatus(false);
    }
}

function updateConnectionStatus(online) {
    const statusEl = elements.connectionStatus;
    const textEl = statusEl.querySelector('.status-text');

    statusEl.classList.remove('online', 'offline');
    statusEl.classList.add(online ? 'online' : 'offline');
    textEl.textContent = online ? 'Online' : 'Offline';
}

// ============================================================================
// LOAD STATS
// ============================================================================

async function loadStats() {
    try {
        const stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' });

        if (stats) {
            elements.statSafe.textContent = formatNumber(stats.safe || 0);
            elements.statWarned.textContent = formatNumber(stats.warned || 0);
            elements.statBlocked.textContent = formatNumber(stats.blocked || 0);
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// ============================================================================
// LOAD CURRENT VERDICT
// ============================================================================

async function loadCurrentVerdict() {
    try {
        // Get verdict from storage
        const result = await chrome.storage.session.get(`verdict_${currentTabId}`);
        const verdict = result[`verdict_${currentTabId}`];

        if (verdict) {
            currentVerdict = verdict;
            updateStatusCard(verdict);
            updateVerdictDetails(verdict);
            updateModelBars(verdict);
        } else {
            // Trigger a scan for the current tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.url && !isInternalUrl(tab.url)) {
                const newVerdict = await chrome.runtime.sendMessage({
                    type: 'GET_VERDICT',
                    url: tab.url,
                });
                currentVerdict = newVerdict;
                updateStatusCard(newVerdict);
                updateVerdictDetails(newVerdict);
                updateModelBars(newVerdict);
            } else {
                showInternalPage();
            }
        }
    } catch (error) {
        console.error('Failed to load verdict:', error);
        showError();
    }
}

// ============================================================================
// UI UPDATES
// ============================================================================

function updateStatusCard(verdict) {
    const card = elements.currentStatus.querySelector('.status-card');
    const iconContainer = card.querySelector('.status-icon');
    const title = card.querySelector('.status-title');

    // Remove loading state
    card.classList.remove('loading', 'safe', 'warning', 'blocked');

    // Clear scan animation
    iconContainer.innerHTML = '';

    let icon, label, status;

    if (verdict.action === 'block' || (verdict.isPhishing && verdict.confidence >= 0.8)) {
        status = 'blocked';
        icon = '🚫';
        label = 'Phishing Detected';
    } else if (verdict.action === 'warn' || (verdict.isPhishing && verdict.confidence >= 0.5)) {
        status = 'warning';
        icon = '⚠️';
        label = 'Suspicious Site';
    } else if (verdict.verdict === 'unknown' || verdict.error) {
        status = 'warning';
        icon = '❓';
        label = 'Unable to Analyze';
    } else {
        status = 'safe';
        icon = '✓';
        label = 'Site is Safe';
    }

    card.classList.add(status);
    iconContainer.textContent = icon;
    title.textContent = label;

    // Add confidence bar
    if (verdict.confidence > 0) {
        let existingBar = card.querySelector('.confidence-bar');
        if (!existingBar) {
            existingBar = document.createElement('div');
            existingBar.className = 'confidence-bar';
            existingBar.innerHTML = '<div class="confidence-fill"></div>';
            card.querySelector('.status-info').appendChild(existingBar);
        }
        const fill = existingBar.querySelector('.confidence-fill');
        fill.style.width = `${verdict.confidence * 100}%`;
    }
}

function updateVerdictDetails(verdict) {
    if (!verdict || verdict.error) {
        elements.verdictDetails.classList.add('hidden');
        return;
    }

    elements.verdictDetails.classList.remove('hidden');

    const details = [
        { label: 'Confidence', value: `${(verdict.confidence * 100).toFixed(1)}%` },
        { label: 'Latency', value: verdict.latency ? `${verdict.latency}ms` : 'N/A' },
        { label: 'Source', value: verdict.fromCache ? 'Cached' : (verdict.offline ? 'Offline' : 'API') },
    ];

    if (verdict.message) {
        details.push({ label: 'Reason', value: verdict.message });
    }

    // Count models
    const mlCount = verdict.mlModels ? Object.keys(verdict.mlModels).length : 0;
    const dlCount = verdict.dlModels ? Object.keys(verdict.dlModels).length : 0;
    if (mlCount + dlCount > 0) {
        details.push({ label: 'Models Used', value: `${mlCount} ML + ${dlCount} DL = ${mlCount + dlCount} total` });
    }

    elements.detailsGrid.innerHTML = details.map(d => `
    <div class="detail-row">
      <span class="detail-label">${d.label}</span>
      <span class="detail-value">${d.value}</span>
    </div>
  `).join('');
}

function updateModelBars(verdict) {
    const models = [];

    // Add ML models
    if (verdict.mlModels) {
        Object.entries(verdict.mlModels).forEach(([name, data]) => {
            models.push({
                name: formatModelName(name),
                type: 'ML',
                confidence: data.probability || 0,
                isPhishing: data.prediction === 1,
            });
        });
    }

    // Add DL models
    if (verdict.dlModels) {
        Object.entries(verdict.dlModels).forEach(([name, data]) => {
            models.push({
                name: formatModelName(name),
                type: 'DL',
                confidence: data.probability || 0,
                isPhishing: data.prediction === 1,
            });
        });
    }

    if (models.length === 0) {
        // Show trusted domain message if no models were used
        if (verdict.message && verdict.message.includes('Trusted')) {
            elements.modelsSection.classList.remove('hidden');
            elements.modelsContent.classList.remove('hidden');
            elements.modelsToggle.classList.add('open');
            elements.modelBars.innerHTML = `
                <div class="model-bar">
                    <div class="model-bar-header">
                        <span class="model-name">Trusted Domain</span>
                        <span class="model-confidence" style="color: var(--accent-green)">Verified Safe</span>
                    </div>
                </div>
            `;
        } else {
            elements.modelsSection.classList.add('hidden');
        }
        return;
    }

    // Show models section expanded by default
    elements.modelsSection.classList.remove('hidden');
    elements.modelsContent.classList.remove('hidden');
    elements.modelsToggle.classList.add('open');

    // Count votes
    const phishingVotes = models.filter(m => m.isPhishing).length;
    const safeVotes = models.filter(m => !m.isPhishing).length;
    const totalModels = models.length;

    // Add vote summary header
    let voteSummary = `
    <div class="model-bar" style="margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1)">
        <div class="model-bar-header">
            <span class="model-name" style="font-weight:600">Ensemble Vote</span>
            <span class="model-confidence">
                <span style="color: var(--accent-red)">${phishingVotes} Phishing</span> / 
                <span style="color: var(--accent-green)">${safeVotes} Safe</span>
                (${totalModels} models)
            </span>
        </div>
    </div>
    `;

    const modelBarsHtml = models.map(m => `
    <div class="model-bar">
      <div class="model-bar-header">
        <span class="model-name">${m.name} <span style="opacity:0.5;font-size:10px">${m.type}</span></span>
        <span class="model-confidence" style="color: ${m.isPhishing ? 'var(--accent-red)' : 'var(--accent-green)'}">
          ${(m.confidence * 100).toFixed(1)}% ${m.isPhishing ? 'Phishing' : 'Safe'}
        </span>
      </div>
      <div class="model-bar-track">
        <div class="model-bar-fill ${m.isPhishing ? 'phishing' : 'safe'}" 
             style="width: ${m.confidence * 100}%"></div>
      </div>
    </div>
  `).join('');

    elements.modelBars.innerHTML = voteSummary + modelBarsHtml;
}

function showInternalPage() {
    const card = elements.currentStatus.querySelector('.status-card');
    const iconContainer = card.querySelector('.status-icon');
    const title = card.querySelector('.status-title');

    card.classList.remove('loading', 'safe', 'warning', 'blocked');
    iconContainer.innerHTML = '🔒';
    title.textContent = 'Internal Page';
    elements.currentUrl.textContent = 'Browser internal page - no scan needed';

    elements.verdictDetails.classList.add('hidden');
    elements.modelsSection.classList.add('hidden');
}

function showError() {
    const card = elements.currentStatus.querySelector('.status-card');
    const iconContainer = card.querySelector('.status-icon');
    const title = card.querySelector('.status-title');

    card.classList.remove('loading');
    card.classList.add('warning');
    iconContainer.innerHTML = '⚠️';
    title.textContent = 'Error';

    elements.verdictDetails.classList.add('hidden');
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Models toggle
    elements.modelsToggle.addEventListener('click', () => {
        elements.modelsToggle.classList.toggle('open');
        elements.modelsContent.classList.toggle('hidden');
    });

    // Rescan button
    elements.rescanBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) {
            // Clear cache and rescan
            await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });

            // Show loading state
            const card = elements.currentStatus.querySelector('.status-card');
            card.classList.add('loading');
            card.querySelector('.status-icon').innerHTML = `
        <div class="scan-animation">
          <div class="scan-ring"></div>
          <div class="scan-ring"></div>
          <div class="scan-ring"></div>
        </div>
      `;
            card.querySelector('.status-title').textContent = 'Rescanning...';

            // Get fresh verdict
            const verdict = await chrome.runtime.sendMessage({
                type: 'GET_VERDICT',
                url: tab.url,
            });

            currentVerdict = verdict;
            updateStatusCard(verdict);
            updateVerdictDetails(verdict);
            updateModelBars(verdict);
            loadStats();
        }
    });

    // Whitelist button
    elements.whitelistBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) {
            const result = await chrome.runtime.sendMessage({
                type: 'WHITELIST_URL',
                url: tab.url,
            });

            if (result.success) {
                alert(`βœ… Domain ${result.domain} has been whitelisted.`);
                // Refresh verdict
                elements.rescanBtn.click();
            }
        }
    });

    // Report button
    elements.reportBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url && currentVerdict) {
            // Here you would send to your reporting endpoint
            chrome.runtime.sendMessage({
                type: 'REPORT_FALSE_POSITIVE',
                url: tab.url,
                verdict: currentVerdict,
            });
            alert('πŸ" Thank you! Your report has been submitted for review.');
        }
    });

    // Settings link
    elements.settingsLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });

    // Help link
    elements.helpLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: 'https://github.com/yourusername/deepshield#readme' });
    });
}

// ============================================================================
// UTILITIES
// ============================================================================

function truncateUrl(url) {
    try {
        const urlObj = new URL(url);
        const display = urlObj.hostname + urlObj.pathname;
        return display.length > 40 ? display.substring(0, 40) + '...' : display;
    } catch {
        return url.substring(0, 40) + '...';
    }
}

function formatNumber(num) {
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'k';
    }
    return num.toString();
}

function formatModelName(name) {
    const names = {
        'xgboost': 'XGBoost',
        'random_forest': 'Random Forest',
        'randomforest': 'Random Forest',
        'charcnn': 'CharCNN',
        'bilstm': 'BiLSTM',
        'transformer': 'Transformer',
    };
    return names[name.toLowerCase()] || name;
}

function isInternalUrl(url) {
    return url.startsWith('chrome://') ||
        url.startsWith('chrome-extension://') ||
        url.startsWith('moz-extension://') ||
        url.startsWith('about:') ||
        url.startsWith('edge://') ||
        url.startsWith('file://');
}

// ============================================================================
// START
// ============================================================================

document.addEventListener('DOMContentLoaded', init);
