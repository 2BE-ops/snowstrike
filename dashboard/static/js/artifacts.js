/**
 * SnowStrike Artifacts - Vulnerability, Credential, Loot, and Host tables
 */

const HexArtifacts = (() => {

    function init() {
        // Tab switching
        // Tab switching is handled by app.js generic tab handler
    }

    function sevBadge(severity) {
        const s = (severity || 'info').toLowerCase();
        return `<span class="badge badge-${s}">${s}</span>`;
    }

    function boolIcon(val) {
        return val ? '<span class="bool-yes">&#x2714;</span>' : '<span class="bool-no">&#x2718;</span>';
    }

    function shortTime(ts) {
        if (!ts) return '--';
        try {
            const d = new Date(ts.includes('T') ? ts : ts + 'Z');
            return d.toLocaleTimeString('en-US', { hour12: false });
        } catch {
            return ts.substring(11, 19) || '--';
        }
    }

    function esc(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ------------------------------------------------------------------
    // Vulnerabilities
    // ------------------------------------------------------------------

    let lastVulns = [];

    function updateVulns(vulns) {
        const tbody = document.getElementById('vulns-tbody');
        const empty = document.getElementById('vulns-empty');
        if (!vulns || vulns.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = '';
            lastVulns = [];
            return;
        }
        empty.style.display = 'none';
        lastVulns = vulns;

        tbody.innerHTML = vulns.map((v, i) => `
            <tr class="vuln-row" data-vuln-idx="${i}">
                <td>${sevBadge(v.severity)}</td>
                <td title="${esc(v.description || '')}">${esc(v.title)}</td>
                <td>${esc(v.host_ip || '')}</td>
                <td>${esc(v.cve_id || '--')}</td>
                <td>${esc(v.agent_source || '')}</td>
                <td>${shortTime(v.created_at)}</td>
            </tr>
            <tr class="vuln-actions-row hidden" id="vuln-actions-${i}">
                <td colspan="6">
                    <div class="vuln-actions-panel">
                        <div class="vuln-actions-header">
                            <span class="vuln-actions-title">${esc(v.title)}</span>
                            ${v.cve_id ? `<span class="vuln-actions-cve">${esc(v.cve_id)}</span>` : ''}
                        </div>
                        <div class="vuln-actions-desc">${esc((v.description || '').substring(0, 300))}${(v.description || '').length > 300 ? '...' : ''}</div>
                        <div class="vuln-actions-buttons">
                            <button class="vuln-btn vuln-btn-exploit" data-vuln-idx="${i}">Exploit</button>
                            <button class="vuln-btn vuln-btn-explore" data-vuln-idx="${i}">Explore Options</button>
                        </div>
                        <div class="vuln-actions-result" id="vuln-result-${i}"></div>
                    </div>
                </td>
            </tr>
        `).join('');

        // Click row to toggle actions
        tbody.querySelectorAll('.vuln-row').forEach(row => {
            row.addEventListener('click', () => {
                const idx = row.dataset.vulnIdx;
                const actionsRow = document.getElementById(`vuln-actions-${idx}`);
                // Close other open panels
                tbody.querySelectorAll('.vuln-actions-row').forEach(r => {
                    if (r.id !== `vuln-actions-${idx}`) r.classList.add('hidden');
                });
                tbody.querySelectorAll('.vuln-row').forEach(r => r.classList.remove('vuln-row-active'));
                actionsRow.classList.toggle('hidden');
                if (!actionsRow.classList.contains('hidden')) {
                    row.classList.add('vuln-row-active');
                }
            });
        });

        // Exploit button
        tbody.querySelectorAll('.vuln-btn-exploit').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = btn.dataset.vulnIdx;
                exploitVuln(parseInt(idx));
            });
        });

        // Explore button
        tbody.querySelectorAll('.vuln-btn-explore').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = btn.dataset.vulnIdx;
                exploreVuln(parseInt(idx));
            });
        });
    }

    function getActiveEngagement() {
        const match = document.cookie.match(new RegExp('(^| )active_engagement=([^;]+)'));
        if (match) return decodeURIComponent(match[2]);
        return null;
    }

    async function exploitVuln(idx) {
        const v = lastVulns[idx];
        if (!v) return;
        const engName = getActiveEngagement();
        if (!engName) return;

        const resultEl = document.getElementById(`vuln-result-${idx}`);
        resultEl.innerHTML = '<div class="vuln-result-loading">Dispatching Attack Agent...</div>';

        try {
            const resp = await fetch(`/api/engagement/${encodeURIComponent(engName)}/exploit-vuln`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: v.title,
                    severity: v.severity,
                    host_ip: v.host_ip,
                    cve_id: v.cve_id,
                    description: v.description,
                }),
            });
            const data = await resp.json();
            resultEl.innerHTML = `<div class="vuln-result-success">
                <div class="vuln-result-status">Attack Agent dispatched</div>
                <div class="vuln-result-detail">${esc(data.message || '')}</div>
                <div class="vuln-result-hint">Watch the Terminal tab for live execution output.</div>
            </div>`;
        } catch (err) {
            resultEl.innerHTML = `<div class="vuln-result-error">Failed: ${esc(err.message)}</div>`;
        }
    }

    async function exploreVuln(idx) {
        const v = lastVulns[idx];
        if (!v) return;
        const engName = getActiveEngagement();
        if (!engName) return;

        const resultEl = document.getElementById(`vuln-result-${idx}`);
        resultEl.innerHTML = '<div class="vuln-result-loading">Analyzing exploitation options...</div>';

        try {
            const resp = await fetch(`/api/engagement/${encodeURIComponent(engName)}/explore-vuln`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: v.title,
                    severity: v.severity,
                    host_ip: v.host_ip,
                    cve_id: v.cve_id,
                    description: v.description,
                }),
            });
            const data = await resp.json();
            const html = typeof marked !== 'undefined' ? marked.parse(data.options || '') : esc(data.options || '');
            resultEl.innerHTML = `<div class="vuln-result-options">${html}</div>`;
        } catch (err) {
            resultEl.innerHTML = `<div class="vuln-result-error">Failed: ${esc(err.message)}</div>`;
        }
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------

    function updateCreds(creds) {
        const tbody = document.getElementById('creds-tbody');
        const empty = document.getElementById('creds-empty');
        if (!creds || creds.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = '';
            return;
        }
        empty.style.display = 'none';
        tbody.innerHTML = creds.map(c => `
            <tr>
                <td>${esc(c.username || '?')}</td>
                <td>${esc(c.credential_type || '--')}</td>
                <td class="hash-cell" title="${esc(c.password_hash || '')}">${esc(c.password_hash || '--')}</td>
                <td>${esc(c.host_ip || '--')}</td>
                <td>${esc(c.source || '--')}</td>
                <td>${boolIcon(c.confirmed)}</td>
            </tr>
        `).join('');
    }

    // ------------------------------------------------------------------
    // Loot
    // ------------------------------------------------------------------

    function updateLoot(lootItems) {
        const tbody = document.getElementById('loot-tbody');
        const empty = document.getElementById('loot-empty');
        if (!lootItems || lootItems.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = '';
            return;
        }
        empty.style.display = 'none';
        tbody.innerHTML = lootItems.map(l => `
            <tr>
                <td>${esc(l.loot_type || '--')}</td>
                <td>${esc(l.description || '--')}</td>
                <td>${esc(l.file_path || '--')}</td>
                <td>${shortTime(l.created_at)}</td>
            </tr>
        `).join('');
    }

    // ------------------------------------------------------------------
    // Hosts
    // ------------------------------------------------------------------

    function updateHosts(hosts) {
        const tbody = document.getElementById('hosts-tbody');
        const empty = document.getElementById('hosts-empty');
        if (!hosts || hosts.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = '';
            return;
        }
        empty.style.display = 'none';
        tbody.innerHTML = hosts.map(h => {
            const services = (h.services || [])
                .map(s => `${s.port}/${s.service_name || '?'}`)
                .join(', ');
            return `
                <tr>
                    <td>${esc(h.ip)}</td>
                    <td>${esc(h.hostname || '--')}</td>
                    <td>${esc(h.os || '--')}</td>
                    <td title="${esc(services)}">${esc(services || 'none')}</td>
                    <td>${shortTime(h.first_seen)}</td>
                </tr>
            `;
        }).join('');
    }

    return {
        init,
        updateVulns,
        updateCreds,
        updateLoot,
        updateHosts,
    };
})();
