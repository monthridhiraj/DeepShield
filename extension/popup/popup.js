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

    // Details(verdict-details)
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

                // Show analyzing state
                const card = elements.currentStatus.querySelector('.status-card');
                card.classList.add('loading');
                card.querySelector('.status-title').textContent = 'Analyzing...';

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
    const urlDisplay = elements.currentUrl;

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
    // Keep URL display

    // Add confidence bar
    // Remove old bar if exists
    const oldBar = card.querySelector('.confidence-bar');
    if (oldBar) oldBar.remove();

    if (verdict.confidence > 0) {
        const bar = document.createElement('div');
        bar.className = 'confidence-bar';
        bar.innerHTML = '<div class="confidence-fill"></div>';
        card.querySelector('.status-info').appendChild(bar);

        // Brief timeout to trigger animation if css supports it
        setTimeout(() => {
            const fill = bar.querySelector('.confidence-fill');
            fill.style.width = `${verdict.confidence * 100}%`;
            // Color based on status
            if (status === 'safe') fill.style.backgroundColor = '#10b981'; // Green
            else if (status === 'blocked') fill.style.backgroundColor = '#ef4444'; // Red
            else fill.style.backgroundColor = '#f59e0b'; // Orange
        }, 10);
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

    if (verdict.message && verdict.message !== 'Safe') {
        // Truncate message if too long
        let msg = verdict.message;
        if (msg.length > 30) msg = msg.substring(0, 30) + '...';
        details.push({ label: 'Reason', value: msg });
    }

    // Model Count
    const mlCount = verdict.mlModels ? Object.keys(verdict.mlModels).length : 0;
    const dlCount = verdict.dlModels ? Object.keys(verdict.dlModels).length : 0;

    // Only show model count if we have models
    if (mlCount + dlCount > 0) {
        // Simplified display
        // details.push({ label: 'Models', value: `${mlCount + dlCount}` });
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

    // If no models (e.g. trusted domain), handle UI
    if (models.length === 0) {
        // If trusted, just hide the section or show a "Trusted" badge
        if (verdict.confidence > 0.98 && !verdict.isPhishing) {
            elements.modelsSection.classList.remove('hidden');
            elements.modelsContent.classList.remove('hidden'); // Show content to see the trusted badge
            elements.modelsToggle.classList.add('open');

            elements.modelBars.innerHTML = `
                <div class="model-bar">
                    <div style="text-align: center; padding: 10px; color: #10b981;">
                        <strong>Verified Trusted Domain</strong><br>
                        <span style="font-size: 0.8em; opacity: 0.8;">Bypassed AI models for performance</span>
                    </div>
                </div>
            `;
            return;
        }

        elements.modelsSection.classList.add('hidden');
        return;
    }

    elements.modelsSection.classList.remove('hidden');
    elements.modelsToggle.classList.remove('open'); // Default closed? User asked it's not working, maybe start closed.
    elements.modelsContent.classList.add('hidden');

    const modelBarsHtml = models.map(m => `
    <div class="model-bar">
      <div class="model-bar-header">
        <span class="model-name">${m.name}</span>
        <span class="model-confidence" style="color: ${m.isPhishing ? '#ef4444' : '#10b981'}">
          ${(m.confidence * 100).toFixed(0)}%
        </span>
      </div>
      <div class="model-bar-track">
        <div class="model-bar-fill ${m.isPhishing ? 'phishing' : 'safe'}" 
             style="width: ${m.confidence * 100}%; background-color: ${m.isPhishing ? '#ef4444' : '#10b981'};"></div>
      </div>
    </div>
  `).join('');

    elements.modelBars.innerHTML = modelBarsHtml;
}

function showInternalPage() {
    const card = elements.currentStatus.querySelector('.status-card');
    const iconContainer = card.querySelector('.status-icon');
    const title = card.querySelector('.status-title');

    card.classList.remove('loading', 'safe', 'warning', 'blocked');
    iconContainer.innerHTML = '🔒';
    title.textContent = 'System Page';
    elements.currentUrl.textContent = 'Internal browser page';

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
    title.textContent = 'Connection Error';

    elements.verdictDetails.classList.add('hidden');
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Models toggle
    if (elements.modelsToggle) {
        elements.modelsToggle.addEventListener('click', (e) => {
            console.log('Toggle clicked');
            elements.modelsToggle.classList.toggle('open');
            elements.modelsContent.classList.toggle('hidden');
            e.stopPropagation(); // Prevent bubbling issues
        });
    }

    // Rescan button
    if (elements.rescanBtn) {
        elements.rescanBtn.addEventListener('click', async () => {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.url) {
                // Clear cache and rescan
                await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });
                loadCurrentVerdict();
            }
        });
    }

    // Whitelist button
    if (elements.whitelistBtn) {
        elements.whitelistBtn.addEventListener('click', async () => {
            // Implementation for whitelisting via background script
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.url) {
                await chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: tab.url });
                loadCurrentVerdict(); // reload
            }
        });
    }

    // Settings Reference
    if (elements.settingsLink) {
        elements.settingsLink.addEventListener('click', () => {
            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
            } else {
                window.open(chrome.runtime.getURL('options.html'));
            }
        });
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

function truncateUrl(url) {
    try {
        const urlObj = new URL(url);
        const display = urlObj.hostname + (urlObj.pathname.length > 1 ? urlObj.pathname : '');
        return display.length > 35 ? display.substring(0, 35) + '...' : display;
    } catch {
        return url.substring(0, 35) + '...';
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
        'bert': 'Transformer (BERT)'
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
