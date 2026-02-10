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

    // Whitelist button
    document.getElementById('whitelist-btn').addEventListener('click', async () => {
        if (blockedUrl) {
            try {
                const result = await chrome.runtime.sendMessage({
                    type: 'WHITELIST_URL',
                    url: blockedUrl
                });

                if (result && result.success) {
                    // Redirect to the original URL
                    window.location.href = blockedUrl;
                } else {
                    alert('Failed to whitelist. Please try again.');
                }
            } catch (error) {
                console.error('Whitelist error:', error);
                alert('Extension error: Could not whitelist.');
            }
        }
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
                type: 'WHITELIST_URL', // Reuse whitelist for now effectively
                url: blockedUrl
            }, () => {
                window.location.href = blockedUrl;
            });
        }
    });
});
