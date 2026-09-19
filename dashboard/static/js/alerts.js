/**
 * SnowStrike Alerts Module
 * Displays alerts from the Kimi-powered alerts agent in a dedicated
 * rail panel, visually separate from the conversation stream.
 */
const HexAlerts = (() => {
    let railEl = null;
    let bodyEl = null;
    let badgeEl = null;
    let alerts = [];

    const SEV_CONFIG = {
        critical: { icon: '\u{1F534}', class: 'alert-critical' },
        high:     { icon: '\u{1F7E0}', class: 'alert-high' },
        medium:   { icon: '\u{1F7E1}', class: 'alert-medium' },
        low:      { icon: '\u{1F535}', class: 'alert-low' },
        info:     { icon: '\u26AA', class: 'alert-info' },
    };

    const CAT_ICONS = {
        vuln: '\u26A0\uFE0F',
        cred: '\u{1F511}',
        access: '\u{1F6AA}',
        agent: '\u{1F916}',
        budget: '\u23F3',
        scope: '\u{1F6A7}',
    };

    function init() {
        railEl = document.getElementById('alertsRail');
        bodyEl = document.getElementById('alertsBody');
        badgeEl = document.getElementById('alertsBadge');

        // Clear button
        document.getElementById('alertsClear')?.addEventListener('click', async () => {
            try {
                await fetch('/api/alerts', { method: 'DELETE' });
                alerts = [];
                render();
            } catch (e) {
                console.error('Failed to clear alerts:', e);
            }
        });

        // Initial load
        loadAlerts();
    }

    async function loadAlerts() {
        try {
            const resp = await fetch('/api/alerts');
            const data = await resp.json();
            alerts = data.alerts || [];
            render();
        } catch (e) {
            // silent on initial load failure
        }
    }

    function handleSSE(data) {
        alerts = data.alerts || [];
        render();
    }

    function render() {
        if (!bodyEl || !badgeEl) return;

        // Badge
        badgeEl.textContent = alerts.length;
        badgeEl.classList.toggle('alerts-badge-active', alerts.length > 0);

        if (alerts.length === 0) {
            bodyEl.innerHTML = '<div class="alerts-empty">No alerts yet</div>';
            return;
        }

        // Render newest first
        const sorted = [...alerts].reverse();
        let html = '';

        for (const alert of sorted) {
            const sev = SEV_CONFIG[alert.severity] || SEV_CONFIG.info;
            const catIcon = CAT_ICONS[alert.category] || '\u25C6';
            const time = formatAlertTime(alert.timestamp);

            html += `<div class="alert-item ${sev.class}">
                <div class="alert-item-header">
                    <span class="alert-sev-icon">${sev.icon}</span>
                    <span class="alert-title">${escHtml(alert.title)}</span>
                </div>
                <div class="alert-detail">${escHtml(alert.detail)}</div>
                <div class="alert-meta">
                    <span>${catIcon} ${alert.category || 'info'}</span>
                    <span>${time}</span>
                </div>
            </div>`;
        }

        bodyEl.innerHTML = html;
    }

    function formatAlertTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts.includes('T') ? ts : ts + 'Z');
            return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        } catch {
            return '';
        }
    }

    function escHtml(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init, loadAlerts, handleSSE };
})();
