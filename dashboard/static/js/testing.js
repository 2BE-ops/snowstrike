/**
 * SnowStrike AI v7.0 - Testing Lab
 *
 * Hidden A/B testing dashboard for model configuration.
 * Access: Triple-click the "v7" badge in the header, or Ctrl+Shift+T.
 */

const HexTestingLab = (() => {
    let panel;
    let activeTab = 'models';

    // Cached data
    let _modelConfigs = [];

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        panel = document.getElementById('testingLab');
        if (!panel) return;

        // Tab switching
        panel.querySelectorAll('.tl-tab').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

        // Close button
        panel.querySelector('#testingLabClose')?.addEventListener('click', close);

        // Keyboard shortcut: Ctrl+Shift+T
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.shiftKey && e.key === 'T') {
                e.preventDefault();
                toggle();
            }
        });

        // Triple-click on version badge
        let clickCount = 0;
        let clickTimer = null;
        const badge = document.querySelector('.brand-version');
        if (badge) {
            badge.style.cursor = 'default';
            badge.addEventListener('click', () => {
                clickCount++;
                clearTimeout(clickTimer);
                if (clickCount >= 3) {
                    clickCount = 0;
                    toggle();
                } else {
                    clickTimer = setTimeout(() => { clickCount = 0; }, 500);
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // Panel visibility
    // ------------------------------------------------------------------

    function open() {
        panel.classList.remove('hidden');
        document.body.classList.add('tl-open');
        loadTab(activeTab);
    }

    function close() {
        panel.classList.add('hidden');
        document.body.classList.remove('tl-open');
    }

    function toggle() {
        if (panel.classList.contains('hidden')) open();
        else close();
    }

    // ------------------------------------------------------------------
    // Tab switching
    // ------------------------------------------------------------------

    function switchTab(tab) {
        activeTab = tab;
        panel.querySelectorAll('.tl-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
        panel.querySelectorAll('.tl-pane').forEach(p => p.classList.toggle('active', p.id === `tl-${tab}`));
        loadTab(tab);
    }

    async function loadTab(tab) {
        switch (tab) {
            case 'models': return loadModelConfigs();
            case 'results': return loadResults();
            case 'costs': return loadCostEstimator();
        }
    }

    // ------------------------------------------------------------------
    // Model Configs Tab
    // ------------------------------------------------------------------

    async function loadModelConfigs() {
        const container = panel.querySelector('#tl-models-body');
        try {
            const resp = await fetch('/api/testing/model-configs');
            const data = await resp.json();
            _modelConfigs = data.configs || [];

            if (!_modelConfigs.length) {
                container.innerHTML = '<div class="tl-empty-msg">No model configs found.</div>';
                return;
            }

            container.innerHTML = _modelConfigs.map(c => `
                <div class="tl-config-card">
                    <div class="tl-config-header">
                        <span class="tl-config-name">${esc(c.name)}</span>
                        <span class="tl-config-tags">${(c.tags||[]).map(t => `<span class="tl-tag">${esc(t)}</span>`).join('')}</span>
                    </div>
                    <div class="tl-config-desc">${esc(c.description)}</div>
                    <div class="tl-config-roles">
                        ${Object.entries(c.roles || {}).map(([role, model]) => `
                            <div class="tl-role-row">
                                <span class="tl-role-label">${esc(role)}</span>
                                <span class="tl-role-model">${esc(model)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        } catch (e) {
            container.innerHTML = `<div class="tl-error">Failed to load: ${e.message}</div>`;
        }
    }

    // ------------------------------------------------------------------
    // Results / Comparison Tab
    // ------------------------------------------------------------------

    async function loadResults() {
        const container = panel.querySelector('#tl-results-body');
        const targetInput = panel.querySelector('#tl-results-target');
        const tagSelect = panel.querySelector('#tl-results-tag');
        const target = targetInput?.value || '';
        const tag = tagSelect?.value || '';

        container.innerHTML = '<div class="tl-loading">Loading results...</div>';

        try {
            let url = '/api/testing/comparison?';
            if (target) url += `target_ip=${encodeURIComponent(target)}&`;
            if (tag) url += `ctf_tag=${encodeURIComponent(tag)}&`;

            const resp = await fetch(url);
            const data = await resp.json();

            if (data.error || !data.summary_table?.length) {
                container.innerHTML = `<div class="tl-empty-msg">${data.error || 'No comparison data available yet.'}</div>`;
                return;
            }

            let html = '';

            // Summary table
            html += `<div class="tl-section-title">Comparison (${data.total_runs} runs)</div>`;
            html += '<div class="tl-table-wrap"><table class="data-table">';
            html += '<thead><tr><th>Run</th><th>Duration</th><th>Cost</th><th>Findings</th><th>Access</th><th>Iterations</th><th>$/Finding</th></tr></thead>';
            html += '<tbody>';
            data.summary_table.forEach(r => {
                const rootBadge = r.root_obtained ? ' <span class="badge sev-critical">root</span>' : (r.shell_obtained ? ' <span class="badge sev-high">shell</span>' : '');
                html += `<tr>
                    <td class="tl-mono">${esc(r.profile)}</td>
                    <td>${esc(r.duration_display)}</td>
                    <td>$${r.cost_usd.toFixed(2)}</td>
                    <td>${r.total_findings}</td>
                    <td>${esc(r.access_achieved)}${rootBadge}</td>
                    <td>${r.iterations}/${r.budget_total}</td>
                    <td>$${r.cost_per_finding.toFixed(2)}</td>
                </tr>`;
            });
            html += '</tbody></table></div>';

            // Analytics cards
            const cost = data.cost_analysis;
            const speed = data.speed_analysis;
            const quality = data.quality_analysis;

            html += '<div class="tl-analytics-grid">';
            html += renderAnalyticsCard('Cost', [
                `Cheapest: $${cost.cheapest.toFixed(2)}`,
                `Average: $${cost.average.toFixed(2)}`,
                `Most expensive: $${cost.most_expensive.toFixed(2)}`,
                cost.cheapest_root ? `Best $/root: ${cost.cheapest_root.profile} ($${cost.cheapest_root.cost_usd.toFixed(2)})` : null,
            ]);
            html += renderAnalyticsCard('Speed', [
                `Fastest: ${formatDuration(speed.fastest)}`,
                `Average: ${formatDuration(speed.average)}`,
                `Slowest: ${formatDuration(speed.slowest)}`,
                speed.fastest_root ? `Fastest root: ${speed.fastest_root.profile} (${speed.fastest_root.duration_display})` : null,
            ]);
            html += renderAnalyticsCard('Quality', [
                `Most findings: ${quality.most_findings}`,
                `Average findings: ${quality.average_findings}`,
                `Root rate: ${quality.root_rate}%`,
                `Shell rate: ${quality.shell_rate}%`,
            ]);
            html += '</div>';

            // Recommendations
            if (data.recommendations?.length) {
                html += '<div class="tl-section-title">Recommendations</div>';
                html += '<div class="tl-recs">';
                data.recommendations.forEach(rec => {
                    html += `<div class="tl-rec">
                        <span class="tl-rec-case">${esc(rec.use_case)}</span>
                        <span class="tl-rec-profile">${esc(rec.profile)}</span>
                        <span class="tl-rec-reason">${esc(rec.reason)}</span>
                    </div>`;
                });
                html += '</div>';
            }

            container.innerHTML = html;
        } catch (e) {
            container.innerHTML = `<div class="tl-error">Failed to load: ${e.message}</div>`;
        }
    }

    function renderAnalyticsCard(title, items) {
        const lines = items.filter(Boolean).map(i => `<div class="tl-analytic-line">${i}</div>`).join('');
        return `<div class="tl-analytic-card"><div class="tl-analytic-title">${title}</div>${lines}</div>`;
    }

    // ------------------------------------------------------------------
    // Cost Estimator Tab
    // ------------------------------------------------------------------

    async function loadCostEstimator() {
        const container = panel.querySelector('#tl-costs-body');
        const tokInput = panel.querySelector('#tl-costs-tokens');
        const tokens = parseInt(tokInput?.value || '100000', 10);

        container.innerHTML = '<div class="tl-loading">Estimating costs...</div>';

        try {
            // Load all configs
            const resp = await fetch('/api/testing/model-configs');
            const data = await resp.json();
            const configs = data.configs || [];

            // Estimate each
            const estimates = [];
            for (const c of configs) {
                const estResp = await fetch(`/api/testing/estimate-cost/${c.name}?tokens_per_agent=${tokens}`);
                const est = await estResp.json();
                estimates.push({ name: c.name, description: c.description, ...est });
            }

            // Sort by cost
            estimates.sort((a, b) => (a.total_usd || 0) - (b.total_usd || 0));

            let html = `<div class="tl-section-title">Cost Estimates (${tokens.toLocaleString()} tokens/agent)</div>`;

            // Summary bar chart
            const maxCost = Math.max(...estimates.map(e => e.total_usd || 0), 0.01);
            html += '<div class="tl-cost-bars">';
            estimates.forEach(est => {
                const pct = ((est.total_usd || 0) / maxCost * 100).toFixed(1);
                html += `<div class="tl-cost-bar-row">
                    <span class="tl-cost-bar-label">${esc(est.name)}</span>
                    <div class="tl-cost-bar-track">
                        <div class="tl-cost-bar-fill" style="width:${pct}%"></div>
                    </div>
                    <span class="tl-cost-bar-value">$${(est.total_usd||0).toFixed(2)}</span>
                </div>`;
            });
            html += '</div>';

            // Detailed breakdown
            html += '<div class="tl-section-title" style="margin-top:24px">Breakdown by Role</div>';
            estimates.forEach(est => {
                html += `<details class="tl-cost-detail"><summary class="tl-cost-detail-summary">${esc(est.name)} — $${(est.total_usd||0).toFixed(2)}</summary>`;
                html += '<table class="data-table"><thead><tr><th>Role</th><th>Model</th><th>Input</th><th>Output</th><th>Total</th></tr></thead><tbody>';
                for (const [role, d] of Object.entries(est.breakdown || {})) {
                    html += `<tr>
                        <td class="tl-mono">${esc(role)}</td>
                        <td class="tl-mono">${esc(d.model)}</td>
                        <td>$${d.input_cost_usd.toFixed(4)}</td>
                        <td>$${d.output_cost_usd.toFixed(4)}</td>
                        <td><strong>$${d.total_usd.toFixed(4)}</strong></td>
                    </tr>`;
                }
                html += '</tbody></table></details>';
            });

            container.innerHTML = html;
        } catch (e) {
            container.innerHTML = `<div class="tl-error">Failed to load: ${e.message}</div>`;
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function esc(s) {
        if (s == null) return '';
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    function formatDuration(secs) {
        if (!secs || secs <= 0) return 'N/A';
        const m = Math.floor(secs / 60);
        const s = Math.floor(secs % 60);
        return m > 60 ? `${Math.floor(m/60)}h ${m%60}m` : `${m}m ${s}s`;
    }

    // Public API
    return { init, open, close, toggle, _refreshResults: loadResults, _refreshCosts: loadCostEstimator };
})();
