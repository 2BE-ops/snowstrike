/**
 * SnowStrike Conversations - Live prompt routes + saved conversation viewer
 */

const HexConversations = (() => {
    let container = null;
    let loaded = false;
    let liveFeedEl = null;
    let savedListEl = null;
    let liveCountEl = null;
    let liveTurns = [];
    let savedConversations = [];
    const liveTurnKeys = new Set();
    const streamingBlocks = new Map();

    function init() {
        container = document.getElementById('agentConvos');
    }

    async function load() {
        if (!container) return;

        try {
            const [liveResp, savedResp] = await Promise.all([
                fetch('/api/live-turns?limit=200').then(r => r.json()),
                fetch('/api/conversations').then(r => r.json()),
            ]);
            liveTurns = [];
            liveTurnKeys.clear();
            savedConversations = savedResp.conversations || [];
            renderDashboard();
            (liveResp.turns || []).forEach(turn => appendLiveTurn(turn, { silent: true }));
            renderSavedList(savedConversations);
            loaded = true;
        } catch (e) {
            container.innerHTML = '<div class="placeholder">Failed to load prompt stream.</div>';
        }
    }

    function renderDashboard() {
        if (!container || container.querySelector('.convo-back-btn')) return;

        container.innerHTML = `
            <div class="prompt-dashboard">
                <section class="prompt-live-panel">
                    <div class="prompt-section-header">
                        <div>
                            <div class="prompt-section-kicker">Live</div>
                            <div class="prompt-section-title">Prompt Routes</div>
                        </div>
                        <div class="prompt-section-meta" id="promptLiveCount">0 events</div>
                    </div>
                    <div class="prompt-live-feed" id="promptLiveFeed">
                        <div class="placeholder">Waiting for prompt traffic...</div>
                    </div>
                </section>
                <section class="prompt-saved-panel">
                    <div class="prompt-section-header">
                        <div>
                            <div class="prompt-section-kicker">Saved</div>
                            <div class="prompt-section-title">Completed Conversations</div>
                        </div>
                        <div class="prompt-section-meta">${savedConversations.length} files</div>
                    </div>
                    <div class="prompt-saved-list" id="promptSavedList"></div>
                </section>
            </div>
        `;

        liveFeedEl = document.getElementById('promptLiveFeed');
        savedListEl = document.getElementById('promptSavedList');
        liveCountEl = document.getElementById('promptLiveCount');
        updateLiveCount();
    }

    function renderSavedList(convos) {
        if (!savedListEl) return;
        if (!convos || convos.length === 0) {
            savedListEl.innerHTML = '<div class="placeholder">No conversations saved yet.</div>';
            return;
        }

        savedListEl.innerHTML = convos.map(c => {
            const hasErrors = c.errors && c.errors.length > 0;
            const ts = c.timestamp ? new Date(c.timestamp).toLocaleString() : '--';
            return `
                <button class="prompt-saved-item${hasErrors ? ' prompt-saved-item-error' : ''}" data-file="${esc(c.filename)}">
                    <span class="prompt-saved-top">
                        <span class="prompt-saved-agent">${esc(c.agent)}</span>
                        <span class="prompt-saved-meta">${c.turns} turns · ${c.duration_seconds}s</span>
                    </span>
                    <span class="prompt-saved-bottom">
                        <span>${esc(c.model || 'unknown')}</span>
                        <span>${esc(ts)}</span>
                    </span>
                </button>
            `;
        }).join('');

        savedListEl.querySelectorAll('.prompt-saved-item').forEach(el => {
            el.addEventListener('click', () => openConversation(el.dataset.file));
        });
    }

    async function openConversation(filename) {
        if (!container || !filename) return;
        try {
            const resp = await fetch(`/api/conversations/${encodeURIComponent(filename)}`);
            const data = await resp.json();
            renderDetail(data);
        } catch (e) {
            container.innerHTML = '<div class="placeholder">Failed to load conversation.</div>';
        }
    }

    function renderDetail(data) {
        const parts = [];

        parts.push('<button class="convo-back-btn" id="convoBack">← Back to prompt stream</button>');
        parts.push(`
            <div class="convo-detail-header">
                <h3>${esc(data.agent)} <span class="convo-model-tag">${esc(data.model)}</span></h3>
                <div class="convo-meta">${data.duration_seconds}s · ${new Date(data.timestamp).toLocaleString()}</div>
            </div>
        `);

        if (data.system_prompt) {
            parts.push(`
                <details class="convo-section">
                    <summary class="convo-section-title">System Prompt (${data.system_prompt.length} chars)</summary>
                    <pre class="convo-prompt-text">${esc(data.system_prompt)}</pre>
                </details>
            `);
        }

        if (data.built_context) {
            parts.push(`
                <details class="convo-section" open>
                    <summary class="convo-section-title">Initial Context</summary>
                    <pre class="convo-prompt-text">${esc(data.built_context)}</pre>
                </details>
            `);
        }

        parts.push('<div class="convo-section-title">Conversation Turns</div>');
        for (const turn of (data.conversation || [])) {
            parts.push(renderConversationTurn(turn));
        }

        if (data.errors && data.errors.length > 0) {
            parts.push('<div class="convo-section-title convo-errors">Errors</div>');
            parts.push('<ul class="convo-error-list">');
            data.errors.forEach(e => parts.push(`<li>${esc(e)}</li>`));
            parts.push('</ul>');
        }

        container.innerHTML = parts.join('');
        document.getElementById('convoBack')?.addEventListener('click', () => {
            renderDashboard();
            liveTurns.forEach(turn => appendLiveTurn(turn, { silent: true, allowExisting: true }));
            renderSavedList(savedConversations);
        });
    }

    function renderConversationTurn(turn) {
        const role = turn.role || 'unknown';
        const roleClass = `convo-role-${role.replace(/[^a-z]/g, '')}`;
        const timestamp = turn.timestamp ? new Date(turn.timestamp).toLocaleTimeString() : '';
        return `
            <div class="convo-turn ${roleClass}">
                <div class="convo-turn-header">
                    <span class="convo-turn-role">${esc(role)}</span>
                    <span class="convo-turn-ts">${timestamp}</span>
                </div>
                ${renderContentBlocks(turn.content, { detailMode: true, target: turn.agent || 'Orchestrator' })}
            </div>
        `;
    }

    function refresh() {
        if (!loaded) load();
    }

    function ensureLiveFeed() {
        if (!container) return false;
        if (!liveFeedEl) renderDashboard();
        if (!liveFeedEl) return false;
        const placeholder = liveFeedEl.querySelector('.placeholder');
        if (placeholder) placeholder.remove();
        return true;
    }

    function appendLiveTurn(turn, opts = {}) {
        if (!turn) return;

        const key = liveTurnKey(turn);
        if (!opts.allowExisting && liveTurnKeys.has(key)) return;
        if (!opts.allowExisting) {
            liveTurnKeys.add(key);
            liveTurns.push(turn);
            if (liveTurns.length > 300) {
                const removed = liveTurns.shift();
                liveTurnKeys.delete(liveTurnKey(removed));
            }
        }

        if (!ensureLiveFeed()) return;
        if (container.querySelector('.convo-back-btn')) return;

        const route = normalizeRoute(turn);
        const streamKey = `${route.agent}:${turn.turn || 0}`;
        if (turn.role === 'assistant' && streamingBlocks.has(streamKey)) {
            const block = streamingBlocks.get(streamKey);
            block.body.innerHTML = renderContentBlocks(turn.content, { target: route.target });
            block.card.classList.remove('prompt-route-streaming');
            block.card.classList.add('prompt-route-complete');
            streamingBlocks.delete(streamKey);
            updateLiveCount();
            if (!opts.silent) scrollLiveToBottom();
            return;
        }

        const card = document.createElement('article');
        card.className = `prompt-route-card prompt-route-${escClass(route.streamKind)}`;
        card.innerHTML = `
            <div class="prompt-route-header">
                <span class="prompt-route-badge">${esc(route.streamKindLabel)}</span>
                <span class="prompt-route-path">${esc(route.source)} → ${esc(route.target)}</span>
                <span class="prompt-route-time">${formatTime(turn.timestamp)}</span>
            </div>
            <div class="prompt-route-body">${renderContentBlocks(turn.content, { target: route.target })}</div>
        `;
        liveFeedEl.appendChild(card);
        updateLiveCount();
        if (!opts.silent) scrollLiveToBottom();
    }

    function startStreamingTurn(agent, turnNumber, model) {
        if (!ensureLiveFeed() || !agent) return;
        if (container.querySelector('.convo-back-btn')) return;

        const key = `${agent}:${turnNumber || 0}`;
        if (streamingBlocks.has(key)) return;

        const card = document.createElement('article');
        card.className = 'prompt-route-card prompt-route-response prompt-route-streaming';
        card.innerHTML = `
            <div class="prompt-route-header">
                <span class="prompt-route-badge">streaming</span>
                <span class="prompt-route-path">${esc(agent)} → Orchestrator</span>
                <span class="prompt-route-time">${model ? esc(model) : 'live'}</span>
            </div>
            <div class="prompt-route-body"><pre class="prompt-route-pre prompt-streaming-text"></pre></div>
        `;
        liveFeedEl.appendChild(card);
        streamingBlocks.set(key, {
            card,
            body: card.querySelector('.prompt-route-body'),
            pre: card.querySelector('.prompt-streaming-text'),
            text: '',
        });
        updateLiveCount();
        scrollLiveToBottom();
    }

    function appendStreamingToken(agent, turnNumber, token) {
        if (!agent || !token) return;
        const key = `${agent}:${turnNumber || 0}`;
        if (!streamingBlocks.has(key)) {
            startStreamingTurn(agent, turnNumber, '');
        }
        const block = streamingBlocks.get(key);
        if (!block) return;
        block.text += token;
        block.pre.textContent = block.text;
        scrollLiveToBottom();
    }

    function completeStreamingTurn(agent, turnNumber) {
        const key = `${agent}:${turnNumber || 0}`;
        const block = streamingBlocks.get(key);
        if (!block) return;
        block.card.classList.remove('prompt-route-streaming');
    }

    function clearLiveStream() {
        liveTurns = [];
        liveTurnKeys.clear();
        streamingBlocks.clear();
        liveFeedEl = null;
        if (container && !container.querySelector('.convo-back-btn')) {
            renderDashboard();
            renderSavedList(savedConversations);
        }
    }

    function renderContentBlocks(content, opts = {}) {
        if (typeof content === 'string') {
            return `<pre class="prompt-route-pre">${esc(content)}</pre>`;
        }
        if (!Array.isArray(content)) {
            return `<pre class="prompt-route-pre">${esc(JSON.stringify(content || {}, null, 2))}</pre>`;
        }
        return content.map(block => {
            if (!block) return '';
            if (block.type === 'text') {
                return `<pre class="prompt-route-pre">${esc(block.text || '')}</pre>`;
            }
            if (block.type === 'tool_use') {
                return `
                    <div class="prompt-inline-route">${esc(opts.target || 'Agent')} → ${esc(block.name || 'tool')}</div>
                    <pre class="prompt-route-pre">${esc(block.input_summary || JSON.stringify(block.input || {}, null, 2))}</pre>
                `;
            }
            if (block.type === 'tool_result') {
                const toolName = block.tool_name || 'tool';
                const rawContent = typeof block.content === 'string' ? block.content : JSON.stringify(block.content || {}, null, 2);
                return `
                    <div class="prompt-inline-route">${esc(toolName)} → ${esc(opts.target || 'Agent')}</div>
                    <pre class="prompt-route-pre">${esc(rawContent)}</pre>
                `;
            }
            return `<pre class="prompt-route-pre">${esc(JSON.stringify(block, null, 2))}</pre>`;
        }).join('');
    }

    function normalizeRoute(turn) {
        const role = turn.role || '';
        const source = turn.source || (role === 'user' ? 'Orchestrator' : role === 'assistant' ? turn.agent : 'Tool Runner');
        const target = turn.target || (role === 'assistant' ? 'Orchestrator' : turn.agent || 'Agent');
        const streamKind = turn.stream_kind || (role === 'user' ? 'context' : role === 'assistant' ? 'response' : 'tool_results');
        return {
            agent: turn.agent || source,
            source,
            target,
            streamKind,
            streamKindLabel: streamKind.replace(/_/g, ' '),
        };
    }

    function liveTurnKey(turn) {
        return [
            turn.session_id || '',
            turn.agent || '',
            turn.role || '',
            turn.turn || 0,
            turn.timestamp || '',
        ].join('|');
    }

    function updateLiveCount() {
        if (liveCountEl) {
            const active = streamingBlocks.size;
            liveCountEl.textContent = `${liveTurns.length} events${active ? ` · ${active} streaming` : ''}`;
        }
    }

    function scrollLiveToBottom() {
        if (liveFeedEl) {
            liveFeedEl.scrollTop = liveFeedEl.scrollHeight;
        }
    }

    function formatTime(ts) {
        if (!ts) return '';
        try {
            return new Date(ts).toLocaleTimeString('en-GB', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            });
        } catch {
            return '';
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

    function escClass(str) {
        return esc(str).replace(/\s+/g, '-').toLowerCase();
    }

    function openByFilename(filename) {
        if (!filename) return;
        document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
        const convosTab = document.querySelector('.drawer-tab[data-tab="convos"]');
        if (convosTab) convosTab.classList.add('active');
        document.querySelectorAll('#drawerContent > div').forEach(c => c.classList.remove('active'));
        const target = document.getElementById('tab-convos');
        if (target) target.classList.add('active');
        openConversation(filename);
    }

    return {
        init,
        load,
        refresh,
        openByFilename,
        appendLiveTurn,
        startStreamingTurn,
        appendStreamingToken,
        completeStreamingTurn,
        clearLiveStream,
    };
})();
