document.addEventListener('DOMContentLoaded', () => {
    // Get URL from query params
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');

    if (blockedUrl) {
        document.getElementById('blocked-url').textContent = blockedUrl;
    } else {
        document.getElementById('blocked-url').textContent = 'Unknown URL';
    }

    // Go Back button
    document.getElementById('go-back-btn').addEventListener('click', () => {
        window.history.go(-2); // Go back 2 steps (skip the block page entry)
        // Fallback if history is empty
        setTimeout(() => {
            window.location.href = 'https://google.com';
        }, 500);
    });

    // Advanced Options toggle
    document.getElementById('advanced-btn').addEventListener('click', () => {
        const advancedOptions = document.getElementById('advanced-options');
        advancedOptions.classList.toggle('hidden');
    });

    // Proceed button (unsafe)
    document.getElementById('proceed-btn').addEventListener('click', () => {
        if (blockedUrl) {
            // We need to tell the background script to allow this temporarily
            // For now, just navigating there might trigger the block again unless we whitelist or ignore
            // A simple implementation is to whitelist it temporarily or just navigate
            // Let's try navigating, but the background script needs to know not to block it again immediately.
            // For MVP, we'll use the whitelist message but maybe with a flag or just distinct logic if needed.
            // Actually, proceeding usually implies "ignore for this session". 
            // Let's just navigate for now, and rely on the user potentially whitelisting if it blocks again.
            // Better: Add to a temporary "ignore" list in background.js.
            // For now, let's treat "Proceed" as "Navigate" and hope the background script doesn't loop block.
            // To prevent loop, we should add it to a session whitelist.

            chrome.runtime.sendMessage({
                type: 'WHITELIST_URL',
                url: blockedUrl
            }, () => {
                window.location.href = blockedUrl;
            });
        }
    });

    // Report Mistake (Safe) button
    document.getElementById('report-safe-btn').addEventListener('click', async () => {
        if (!blockedUrl) return;

        const btn = document.getElementById('report-safe-btn');
        btn.textContent = 'Reporting...';
        btn.disabled = true;

        try {
            // 1. Send feedback to API
            const response = await fetch('http://localhost:8000/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: blockedUrl,
                    verdict: 'safe'
                })
            });

            if (response.ok) {
                // 2. Also whitelist locally for instant access
                chrome.runtime.sendMessage({
                    type: 'WHITELIST_URL',
                    url: blockedUrl
                }, () => {
                    alert('Thanks! We have marked this site as Safe.');
                    window.location.href = blockedUrl;
                });
            } else {
                throw new Error('API Error');
            }
        } catch (error) {
            console.error('Feedback failed:', error);
            alert('Could not report mistake. Please try again.');
            btn.textContent = 'Report Mistake (Safe)';
            btn.disabled = false;
        }
    });
});
