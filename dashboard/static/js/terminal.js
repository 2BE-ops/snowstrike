/**
 * SnowStrike Mission Control
 *
 * Replaces the old split "agent cards + terminal window" tab with a unified
 * operations console: agent rail, live/recent operations stream, and detail
 * pane for the selected operation.
 */

const HexAgentCatalog = window.HexAgentCatalog || (() => {
    const AGENT_ALIASES = {
        'BinaryRE Agent': 'Binary RE Agent',
    };

    const AGENT_META = {
        'Recon Agent':      { short: 'RECON',     icon: '🔍', color: '#2E8B57', desc: 'Network scanning and enumeration' },
        'OSINT Agent':      { short: 'OSINT',     icon: '🔎', color: '#4A90C4', desc: 'Passive intelligence gathering' },
        'WebApp Agent':     { short: 'WEBAPP',    icon: '🌐', color: '#4A7FC4', desc: 'Web vulnerability testing' },
        'Browser Agent':    { short: 'BROWSER',   icon: '🧭', color: '#4285F4', desc: 'Headless browser automation' },
        'Attack Agent':     { short: 'ATTACK',    icon: '⚔️', color: '#C44A4A', desc: 'Exploitation and privilege escalation' },
        'Cloud Agent':      { short: 'CLOUD',     icon: '☁', color: '#7E57C2', desc: 'Cloud infrastructure assessment' },
        'Binary RE Agent':  { short: 'BINARY',    icon: '⚙', color: '#A67C2E', desc: 'Binary analysis and reverse engineering' },
        'BinaryRE Agent':   { short: 'BINARY',    icon: '⚙', color: '#A67C2E', desc: 'Binary analysis and reverse engineering' },
        'Forensics Agent':  { short: 'FORENSICS', icon: '🧪', color: '#6C7A89', desc: 'Forensics, stego, and crypto' },
        'Reporting Agent':  { short: 'REPORT',    icon: '📋', color: '#7C7C7C', desc: 'Report generation and synthesis' },
    };

    const DISPLAY_ORDER = [
        'Recon Agent',
        'OSINT Agent',
        'WebApp Agent',
        'Browser Agent',
        'Attack Agent',
        'Cloud Agent',
        'Binary RE Agent',
        'Forensics Agent',
        'Reporting Agent',
    ];

    function canonicalAgentName(agentName) {
        return AGENT_ALIASES[agentName] || agentName;
    }

    function getMeta(agentName) {
        const canonicalName = canonicalAgentName(agentName);
        return AGENT_META[canonicalName] || {
            short: canonicalName.replace(' Agent', '').toUpperCase(),
            icon: '◆',
            color: '#8b949e',
            desc: 'Agent activity',
        };
    }

    function getDisplayOrder() {
        return DISPLAY_ORDER.map(canonicalAgentName);
    }

    return {
        AGENT_ALIASES,
        AGENT_META,
        DISPLAY_ORDER: getDisplayOrder(),
        canonicalAgentName,
        getDisplayOrder,
        getMeta,
    };
})();

window.HexAgentCatalog = HexAgentCatalog;

const HexTerminals = (() => {
    const ALL_AGENTS = '__all_agents__';
    const LIVE_PREVIEW_LINES = 14;
    const DETAIL_PREVIEW_LINES = 20;
    const RECENT_OPERATION_LIMIT = 60;

    let agents = {};
    let container = null;
    let selectedAgent = ALL_AGENTS;
    let selectedOperationKey = '';
    let currentPhase = '';
    let completedPhases = [];
    let renderQueued = false;

    function buildEmptyAgentState() {
        return {
            executions: [],
            executionIds: new Set(),
            activeRuns: {},
            stats: {
                tool_runs: 0,
                successes: 0,
                total_duration: 0,
                errors: [],
            },
            todo: null,
        };
    }

    function init(containerId) {
        container = document.getElementById(containerId);
        seedRoster();
        render();
    }

    function ensureAgent(agentName) {
        if (!agentName) return null;
        const canonicalName = HexAgentCatalog.canonicalAgentName(agentName);
        if (!agents[canonicalName]) {
            agents[canonicalName] = buildEmptyAgentState();
        }
        return agents[canonicalName];
    }

    function seedRoster() {
        HexAgentCatalog.getDisplayOrder().forEach(name => ensureAgent(name));
    }

    function scheduleRender() {
        if (!container || renderQueued) return;
        renderQueued = true;
        window.requestAnimationFrame(() => {
            renderQueued = false;
            render();
        });
    }

    function setAgentStats(agentStats, opts = {}) {
        currentPhase = opts.phase || '';
        completedPhases = Array.isArray(opts.completedPhases) ? opts.completedPhases : [];
        const agentTodos = opts.agentTodos || {};

        seedRoster();
        Object.values(agents).forEach(agent => {
            agent.stats = {
                tool_runs: 0,
                successes: 0,
                total_duration: 0,
                errors: [],
            };
            agent.todo = null;
        });

        for (const stat of (agentStats || [])) {
            const agent = ensureAgent(stat.agent);
            if (!agent) continue;
            agent.stats = {
                tool_runs: Number(stat.tool_runs || 0),
                successes: Number(stat.successes || 0),
                total_duration: Number(stat.total_duration || 0),
                errors: Array.isArray(stat.errors) ? stat.errors : [],
            };
        }

        for (const [agentName, todo] of Object.entries(agentTodos)) {
            const agent = ensureAgent(agentName);
            if (agent) agent.todo = todo;
        }

        scheduleRender();
    }

    function setActivityFeed(executions) {
        for (const execution of (executions || [])) {
            ensureAgent(execution.agent);
        }
        scheduleRender();
    }

    function render() {
        if (!container) return;

        seedRoster();
        const liveOperations = getLiveOperations(selectedAgent);
        const recentOperations = getRecentOperations(selectedAgent);
        const selected = resolveSelectedOperation(liveOperations, recentOperations);

        container.innerHTML = `
            <div class="mission-control-shell">
                <aside class="mc-rail">
                    ${renderRail()}
                </aside>
                <section class="mc-stream-pane">
                    ${renderStream(liveOperations, recentOperations, selected)}
                </section>
                <aside class="mc-detail-pane">
                    ${renderDetail(selected, liveOperations, recentOperations)}
                </aside>
            </div>
        `;

        bindEvents();
    }

    function renderRail() {
        const activeAgentCount = getAgentRoster().filter(name => Object.keys(agents[name].activeRuns).length > 0).length;
        const liveCount = getLiveOperations(ALL_AGENTS).length;
        const failedCount = getRecentOperations(ALL_AGENTS).filter(isExecutionFailure).length;

        return `
            <div class="mc-rail-header">
                <div>
                    <div class="mc-kicker">Mission Control</div>
                    <div class="mc-title">Agent Operations</div>
                </div>
                <div class="mc-rail-summary">${activeAgentCount} active · ${liveCount} live</div>
            </div>
            <button class="mc-agent-chip mc-agent-chip-all${selectedAgent === ALL_AGENTS ? ' active' : ''}" data-agent="${ALL_AGENTS}">
                <div class="mc-agent-copy">
                    <div class="mc-agent-top">
                        <span class="mc-agent-name">All Agents</span>
                        <span class="mc-agent-badge">${failedCount} fail</span>
                    </div>
                    <div class="mc-agent-bottom">Unified operations view across all active agents.</div>
                </div>
            </button>
            <div class="mc-agent-list">
                ${getAgentRoster().map(renderAgentChip).join('')}
            </div>
        `;
    }

    function renderAgentChip(agentName) {
        const meta = HexAgentCatalog.getMeta(agentName);
        const agent = ensureAgent(agentName);
        const activeRuns = Object.values(agent.activeRuns).sort(sortByTimestampDesc);
        const lastExecution = getLatestExecution(agent);
        const stateLabel = window.HexAvatars ? HexAvatars.getState(agentName) : 'sleeping';
        const failureCount = getFailureCount(agent);
        const totalRuns = Math.max(agent.stats.tool_runs || 0, agent.executions.length);
        const todoPercent = Math.round(Number(agent.todo?.progress?.percent || 0));
        const secondary = activeRuns.length
            ? `${activeRuns[0].tool || 'tool'} in progress`
            : lastExecution
                ? `${formatOutcomeLabel(lastExecution)} · ${lastExecution.tool_name || 'tool'}`
                : meta.desc;
        const badges = [
            activeRuns.length ? `<span class="mc-badge live">${activeRuns.length} live</span>` : '',
            failureCount ? `<span class="mc-badge fail">${failureCount} fail</span>` : '',
            todoPercent ? `<span class="mc-badge todo">${todoPercent}% todo</span>` : '',
        ].join('');

        return `
            <button class="mc-agent-chip${selectedAgent === agentName ? ' active' : ''}" data-agent="${escHtml(agentName)}" style="--agent-color:${meta.color}">
                <div class="mc-agent-avatar">
                    ${renderAgentAvatar(agentName, meta)}
                </div>
                <div class="mc-agent-copy">
                    <div class="mc-agent-top">
                        <span class="mc-agent-name">${escHtml(meta.short)}</span>
                        <span class="mc-agent-state">${escHtml(stateLabel)}</span>
                    </div>
                    <div class="mc-agent-bottom">${escHtml(secondary)}</div>
                    <div class="mc-agent-metrics">
                        <span>${totalRuns} ops</span>
                        <span>${formatDuration(agent.stats.total_duration || 0)}</span>
                        ${badges}
                    </div>
                    ${renderMiniTodo(agent.todo)}
                </div>
            </button>
        `;
    }

    function renderStream(liveOperations, recentOperations, selected) {
        const filterName = selectedAgent === ALL_AGENTS
            ? 'All Agents'
            : HexAgentCatalog.getMeta(selectedAgent).short;
        const selectedTone = selected?.type === 'live'
            ? 'Live'
            : selected?.type === 'execution'
                ? 'Selected'
                : 'Idle';

        return `
            <div class="mc-stream-header">
                <div>
                    <div class="mc-kicker">Operations Feed</div>
                    <div class="mc-title">${escHtml(filterName)}</div>
                </div>
                <div class="mc-stream-meta">
                    <span>${currentPhase || 'Unknown phase'}</span>
                    <span>${completedPhases.length} completed</span>
                    <span>${selectedTone}</span>
                </div>
            </div>
            <div class="mc-stream-body">
                <section class="mc-section">
                    <div class="mc-section-header">
                        <span class="mc-section-title">Active Operations</span>
                        <span class="mc-section-meta">${liveOperations.length}</span>
                    </div>
                    <div class="mc-operation-list">
                        ${liveOperations.length ? liveOperations.map(renderLiveOperationCard).join('') : '<div class="mc-empty">No active commands right now.</div>'}
                    </div>
                </section>
                <section class="mc-section">
                    <div class="mc-section-header">
                        <span class="mc-section-title">Recent Operations</span>
                        <span class="mc-section-meta">${recentOperations.length}</span>
                    </div>
                    <div class="mc-operation-list">
                        ${recentOperations.length ? recentOperations.map(renderExecutionCard).join('') : '<div class="mc-empty">No completed operations yet.</div>'}
                    </div>
                </section>
            </div>
        `;
    }

    function renderLiveOperationCard(op) {
        const meta = HexAgentCatalog.getMeta(op.agent);
        const run = op.run;
        const preview = tailLines(run.lines || [], LIVE_PREVIEW_LINES).join('\n') || 'Waiting for tool output...';

        return `
            <article class="mc-operation-card live${selectedOperationKey === op.key ? ' selected' : ''}" data-operation-key="${escHtml(op.key)}" style="--agent-color:${meta.color}">
                <div class="mc-operation-top">
                    <span class="mc-operation-agent">${escHtml(meta.short)}</span>
                    <span class="mc-operation-tool">${escHtml(run.tool || 'tool')}</span>
                    <span class="mc-operation-time">${formatTime(run.started_at)}</span>
                </div>
                <div class="mc-operation-command">${escHtml(run.command || '$ pending')}</div>
                <pre class="mc-operation-preview" data-live-output="${escHtml(run.run_id)}">${escHtml(preview)}</pre>
            </article>
        `;
    }

    function renderExecutionCard(execution) {
        const meta = HexAgentCatalog.getMeta(execution.agent);
        const tone = getOutcomeTone(execution);
        const preview = getExecutionPreview(execution, DETAIL_PREVIEW_LINES);
        const duration = execution.duration_seconds != null
            ? formatDuration(Number(execution.duration_seconds || 0))
            : 'n/a';
        const badges = [
            execution.outcome_kind ? `<span class="mc-inline-badge ${tone}">${escHtml(execution.outcome_kind.replace(/_/g, ' '))}</span>` : '',
            execution.failure_category ? `<span class="mc-inline-badge neutral">${escHtml(execution.failure_category)}</span>` : '',
        ].join('');

        return `
            <article class="mc-operation-card ${tone}${selectedOperationKey === execution.key ? ' selected' : ''}" data-operation-key="${escHtml(execution.key)}" style="--agent-color:${meta.color}">
                <div class="mc-operation-top">
                    <span class="mc-operation-agent">${escHtml(meta.short)}</span>
                    <span class="mc-operation-tool">${escHtml(execution.tool_name || 'tool')}</span>
                    <span class="mc-operation-time">${formatTime(execution.created_at)}</span>
                </div>
                <div class="mc-operation-command">${escHtml(execution.command || execution.tool_name || '')}</div>
                <div class="mc-operation-summary">${escHtml(preview || 'No summarized output saved.')}</div>
                <div class="mc-operation-foot">
                    <span>${duration}</span>
                    ${badges}
                </div>
            </article>
        `;
    }

    function renderDetail(selected, liveOperations, recentOperations) {
        if (selected?.type === 'live') {
            return renderLiveDetail(selected.operation);
        }
        if (selected?.type === 'execution') {
            return renderExecutionDetail(selected.operation);
        }
        return renderOverviewDetail(liveOperations, recentOperations);
    }

    function renderLiveDetail(op) {
        const meta = HexAgentCatalog.getMeta(op.agent);
        const run = op.run;
        const output = (run.lines || []).join('\n') || 'Waiting for live output...';

        return `
            <div class="mc-detail-header" style="--agent-color:${meta.color}">
                <div class="mc-kicker">Live Run</div>
                <div class="mc-title">${escHtml(meta.short)} · ${escHtml(run.tool || 'tool')}</div>
                <div class="mc-detail-meta">${formatTime(run.started_at)} · ${escHtml(run.command || 'No command captured')}</div>
            </div>
            <div class="mc-detail-body">
                <div class="mc-detail-grid">
                    <div class="mc-detail-stat"><span>Agent</span><strong>${escHtml(meta.short)}</strong></div>
                    <div class="mc-detail-stat"><span>Status</span><strong>streaming</strong></div>
                    <div class="mc-detail-stat"><span>Command</span><strong>${escHtml(run.command || 'pending')}</strong></div>
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Live Output</div>
                    <pre class="mc-detail-output" data-detail-live-output="${escHtml(run.run_id)}">${escHtml(output)}</pre>
                </div>
            </div>
        `;
    }

    function renderExecutionDetail(execution) {
        const meta = HexAgentCatalog.getMeta(execution.agent);
        const tone = getOutcomeTone(execution);
        const detailOutput = execution._rawLoaded
            ? execution._rawLoaded
            : (execution.raw_preview || execution.compacted_summary || '[no output captured]');
        const canLoadRaw = execution.id && execution.raw_output_path && !execution._rawLoaded;
        const duration = execution.duration_seconds != null
            ? formatDuration(Number(execution.duration_seconds || 0))
            : 'n/a';

        return `
            <div class="mc-detail-header ${tone}" style="--agent-color:${meta.color}">
                <div class="mc-kicker">Operation Detail</div>
                <div class="mc-title">${escHtml(meta.short)} · ${escHtml(execution.tool_name || 'tool')}</div>
                <div class="mc-detail-meta">${formatTime(execution.created_at)} · ${duration}</div>
            </div>
            <div class="mc-detail-body">
                <div class="mc-detail-grid">
                    <div class="mc-detail-stat"><span>Agent</span><strong>${escHtml(meta.short)}</strong></div>
                    <div class="mc-detail-stat"><span>Outcome</span><strong>${escHtml(formatOutcomeLabel(execution))}</strong></div>
                    <div class="mc-detail-stat"><span>Tool</span><strong>${escHtml(execution.tool_name || 'tool')}</strong></div>
                    <div class="mc-detail-stat"><span>Command</span><strong>${escHtml(execution.command || 'n/a')}</strong></div>
                    <div class="mc-detail-stat"><span>Failure Category</span><strong>${escHtml(execution.failure_category || 'n/a')}</strong></div>
                    <div class="mc-detail-stat"><span>Outcome Kind</span><strong>${escHtml(execution.outcome_kind || 'n/a')}</strong></div>
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Summary</div>
                    <div class="mc-detail-summary">${escHtml(execution.compacted_summary || 'No compacted summary recorded.')}</div>
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Output</div>
                    <pre class="mc-detail-output">${escHtml(detailOutput)}</pre>
                    ${canLoadRaw ? `<button class="mc-load-raw" data-exec-id="${escHtml(String(execution.id))}">Load full raw output</button>` : ''}
                </div>
            </div>
        `;
    }

    function renderOverviewDetail(liveOperations, recentOperations) {
        if (selectedAgent !== ALL_AGENTS) {
            return renderAgentOverview(selectedAgent);
        }

        const roster = getAgentRoster();
        const activeAgents = roster.filter(name => Object.keys(agents[name].activeRuns).length > 0);
        const lastFailures = recentOperations.filter(isExecutionFailure).slice(0, 5);

        return `
            <div class="mc-detail-header neutral">
                <div class="mc-kicker">Overview</div>
                <div class="mc-title">${selectedAgent === ALL_AGENTS ? 'Engagement Mission Control' : `${escHtml(HexAgentCatalog.getMeta(selectedAgent).short)} Focus`}</div>
                <div class="mc-detail-meta">${currentPhase || 'Unknown phase'} · ${completedPhases.length} completed phases</div>
            </div>
            <div class="mc-detail-body">
                <div class="mc-detail-grid">
                    <div class="mc-detail-stat"><span>Agents</span><strong>${roster.length}</strong></div>
                    <div class="mc-detail-stat"><span>Active</span><strong>${activeAgents.length}</strong></div>
                    <div class="mc-detail-stat"><span>Live Runs</span><strong>${liveOperations.length}</strong></div>
                    <div class="mc-detail-stat"><span>Recent Ops</span><strong>${recentOperations.length}</strong></div>
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Active Agents</div>
                    ${activeAgents.length
                        ? `<div class="mc-detail-list">${activeAgents.map(renderActiveAgentSummary).join('')}</div>`
                        : '<div class="mc-empty compact">No agents are actively running tools.</div>'}
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Recent Failures</div>
                    ${lastFailures.length
                        ? `<div class="mc-detail-list">${lastFailures.map(renderFailureSummary).join('')}</div>`
                        : '<div class="mc-empty compact">No recent failed operations.</div>'}
                </div>
            </div>
        `;
    }

    function renderAgentOverview(agentName) {
        const agent = ensureAgent(agentName);
        const meta = HexAgentCatalog.getMeta(agentName);
        const liveRuns = Object.values(agent.activeRuns).sort(sortByTimestampDesc);
        const recentRuns = agent.executions.slice().sort(sortExecutionDesc).slice(0, 5);
        const totalRuns = Math.max(agent.stats.tool_runs || 0, agent.executions.length);
        const failureCount = getFailureCount(agent);

        return `
            <div class="mc-detail-header neutral" style="--agent-color:${meta.color}">
                <div class="mc-kicker">Agent Focus</div>
                <div class="mc-title">${escHtml(meta.short)} Mission Board</div>
                <div class="mc-detail-meta">${escHtml(meta.desc)} · ${liveRuns.length} live</div>
            </div>
            <div class="mc-detail-body">
                <div class="mc-detail-grid">
                    <div class="mc-detail-stat"><span>Total Ops</span><strong>${totalRuns}</strong></div>
                    <div class="mc-detail-stat"><span>Successes</span><strong>${Number(agent.stats.successes || 0)}</strong></div>
                    <div class="mc-detail-stat"><span>Failures</span><strong>${failureCount}</strong></div>
                    <div class="mc-detail-stat"><span>Runtime</span><strong>${formatDuration(agent.stats.total_duration || 0)}</strong></div>
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Checklist</div>
                    ${renderTodoDetail(agent.todo)}
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Current Runs</div>
                    ${liveRuns.length
                        ? `<div class="mc-detail-list">${liveRuns.map(run => renderAgentLiveRun(agentName, run)).join('')}</div>`
                        : '<div class="mc-empty compact">No live tool runs for this agent.</div>'}
                </div>
                <div class="mc-detail-section">
                    <div class="mc-detail-section-title">Recent Operations</div>
                    ${recentRuns.length
                        ? `<div class="mc-detail-list">${recentRuns.map(run => renderAgentRecentRun(run)).join('')}</div>`
                        : '<div class="mc-empty compact">No completed operations yet.</div>'}
                </div>
            </div>
        `;
    }

    function renderActiveAgentSummary(agentName) {
        const agent = ensureAgent(agentName);
        const meta = HexAgentCatalog.getMeta(agentName);
        const currentRun = Object.values(agent.activeRuns).sort(sortByTimestampDesc)[0];
        return `
            <button class="mc-detail-list-item" data-agent="${escHtml(agentName)}">
                <span class="mc-detail-list-label">${escHtml(meta.short)}</span>
                <span class="mc-detail-list-text">${escHtml(currentRun?.tool || 'tool')} · ${formatTime(currentRun?.started_at)}</span>
            </button>
        `;
    }

    function renderFailureSummary(execution) {
        const meta = HexAgentCatalog.getMeta(execution.agent);
        return `
            <button class="mc-detail-list-item" data-operation-key="${escHtml(execution.key)}">
                <span class="mc-detail-list-label">${escHtml(meta.short)}</span>
                <span class="mc-detail-list-text">${escHtml(execution.tool_name || 'tool')} · ${escHtml(execution.failure_category || formatOutcomeLabel(execution))}</span>
            </button>
        `;
    }

    function renderAgentLiveRun(agentName, run) {
        return `
            <button class="mc-detail-list-item" data-operation-key="${escHtml(operationKeyForRun(agentName, run))}">
                <span class="mc-detail-list-label">${escHtml(run.tool || 'tool')}</span>
                <span class="mc-detail-list-text">${formatTime(run.started_at)}</span>
            </button>
        `;
    }

    function renderAgentRecentRun(execution) {
        return `
            <button class="mc-detail-list-item" data-operation-key="${escHtml(execution.key)}">
                <span class="mc-detail-list-label">${escHtml(execution.tool_name || 'tool')}</span>
                <span class="mc-detail-list-text">${escHtml(formatOutcomeLabel(execution))}</span>
            </button>
        `;
    }

    function renderMiniTodo(todo) {
        if (!todo || !todo.progress || !Number(todo.progress.total || 0)) {
            return '';
        }
        const percent = Math.max(0, Math.min(100, Number(todo.progress.percent || 0)));
        return `
            <div class="mc-agent-progress">
                <span style="width:${percent}%"></span>
            </div>
        `;
    }

    function renderTodoDetail(todo) {
        if (!todo || !todo.progress) {
            return '<div class="mc-empty compact">No active checklist for this agent.</div>';
        }

        const progress = todo.progress || {};
        const completed = Number(progress.completed || 0);
        const total = Number(progress.total || 0);
        const percent = Math.max(0, Math.min(100, Number(progress.percent || 0)));
        const items = Array.isArray(todo.items) ? todo.items : [];
        const importantItems = items
            .filter(item => ['primary_assignment', 'definition_of_done'].includes(item.group || ''))
            .slice(0, 6);

        return `
            <div class="mc-todo-card">
                <div class="mc-todo-top">
                    <span class="mc-todo-label">${completed}/${total} complete</span>
                    <span class="mc-todo-status">${escHtml(todo.status || 'in_progress')}</span>
                </div>
                <div class="mc-agent-progress"><span style="width:${percent}%"></span></div>
                <div class="mc-todo-items">
                    ${importantItems.length
                        ? importantItems.map(item => `<div class="mc-todo-item ${escHtml((item.status || 'pending').toLowerCase())}">${escHtml(item.text || '')}</div>`).join('')
                        : '<div class="mc-todo-item pending">No checklist items yet.</div>'}
                </div>
            </div>
        `;
    }

    function renderAgentAvatar(agentName, meta) {
        if (window.HexAvatars && HexAvatars.CHARACTERS[HexAgentCatalog.canonicalAgentName(agentName)]) {
            return HexAvatars.renderAvatar(agentName);
        }
        return `<span class="mc-agent-fallback">${escHtml(meta.icon)}</span>`;
    }

    function bindEvents() {
        if (!container) return;

        container.querySelectorAll('.mc-agent-chip[data-agent], .mc-detail-list-item[data-agent]').forEach(el => {
            el.addEventListener('click', (event) => {
                const agentName = event.currentTarget.dataset.agent;
                if (!agentName) return;
                selectedAgent = agentName === ALL_AGENTS ? ALL_AGENTS : HexAgentCatalog.canonicalAgentName(agentName);
                selectedOperationKey = '';
                render();
            });
        });

        container.querySelectorAll('.mc-operation-card[data-operation-key], .mc-detail-list-item[data-operation-key]').forEach(el => {
            el.addEventListener('click', (event) => {
                const key = event.currentTarget.dataset.operationKey;
                if (!key) return;
                selectedOperationKey = key;
                render();
            });
        });

        container.querySelectorAll('.mc-load-raw').forEach(btn => {
            btn.addEventListener('click', async (event) => {
                event.stopPropagation();
                const execId = btn.dataset.execId;
                if (!execId) return;
                btn.disabled = true;
                btn.textContent = 'Loading...';
                try {
                    const response = await fetch(`/api/tool-executions/${execId}/raw`);
                    const data = await response.json();
                    const execution = findExecutionById(execId);
                    if (execution) {
                        execution._rawLoaded = data.raw || '[no output]';
                    }
                    render();
                } catch {
                    btn.textContent = 'Failed to load';
                    btn.disabled = false;
                }
            });
        });
    }

    function writeExecution(agentName, execution) {
        const canonicalName = HexAgentCatalog.canonicalAgentName(agentName);
        const agent = ensureAgent(canonicalName);
        if (!agent) return;

        const normalized = normalizeExecution(execution, canonicalName);
        const execId = normalized.id != null ? String(normalized.id) : '';
        if (execId && agent.executionIds.has(execId)) return;

        agent.executions.push(normalized);
        agent.executions.sort(sortExecutionDesc);
        if (execId) agent.executionIds.add(execId);

        if (normalized.run_id && agent.activeRuns[normalized.run_id]) {
            const liveKey = operationKeyForRun(canonicalName, { run_id: normalized.run_id });
            if (selectedOperationKey === liveKey) {
                selectedOperationKey = normalized.key;
            }
            delete agent.activeRuns[normalized.run_id];
        }

        scheduleRender();
    }

    function writeToolStart(agentName, payload) {
        const canonicalName = HexAgentCatalog.canonicalAgentName(agentName);
        const agent = ensureAgent(canonicalName);
        if (!agent) return;

        const runId = payload.run_id || `${payload.tool || 'tool'}-${Date.now()}`;
        agent.activeRuns[runId] = {
            run_id: runId,
            tool: payload.tool || 'tool',
            command: payload.command || '',
            lines: [],
            started_at: payload.started_at || new Date().toISOString(),
            success: null,
        };

        scheduleRender();
    }

    function writeToolLine(agentName, toolName, line, payload = {}) {
        const canonicalName = HexAgentCatalog.canonicalAgentName(agentName);
        const agent = ensureAgent(canonicalName);
        if (!agent) return;

        let runId = payload.run_id || findLatestRun(agent, toolName);
        if (!runId) {
            runId = `${toolName || 'tool'}-${Date.now()}`;
            writeToolStart(agentName, { tool: toolName, command: '', run_id: runId });
        }

        const run = agent.activeRuns[runId];
        if (!run) return;

        run.lines.push(line);
        if (run.lines.length > 500) run.lines = run.lines.slice(-500);
        updateLiveOutputDom(run);
    }

    function writeToolComplete(agentName, payload) {
        const canonicalName = HexAgentCatalog.canonicalAgentName(agentName);
        const agent = ensureAgent(canonicalName);
        if (!agent) return;

        const runId = payload.run_id || findLatestRun(agent, payload.tool);
        const run = runId ? agent.activeRuns[runId] : null;
        if (!run) return;

        run.success = payload.success;
        run.duration_seconds = payload.duration;
        scheduleRender();
    }

    function writeMessage(agentName) {
        ensureAgent(HexAgentCatalog.canonicalAgentName(agentName));
        scheduleRender();
    }

    function clearAll() {
        Object.keys(agents).forEach(name => {
            agents[name] = buildEmptyAgentState();
        });
        selectedOperationKey = '';
        scheduleRender();
    }

    function reset() {
        agents = {};
        selectedAgent = ALL_AGENTS;
        selectedOperationKey = '';
        currentPhase = '';
        completedPhases = [];
        seedRoster();
        render();
    }

    function fitAll() {}

    function getAgentNames() {
        return Object.keys(agents);
    }

    function getActiveAgent() {
        return selectedAgent === ALL_AGENTS ? null : selectedAgent;
    }

    function getAgentRoster() {
        const seen = new Set();
        const roster = [];

        HexAgentCatalog.getDisplayOrder().forEach(name => {
            const canonicalName = HexAgentCatalog.canonicalAgentName(name);
            seen.add(canonicalName);
            roster.push(canonicalName);
        });

        Object.keys(agents).sort().forEach(name => {
            const canonicalName = HexAgentCatalog.canonicalAgentName(name);
            if (seen.has(canonicalName)) return;
            seen.add(canonicalName);
            roster.push(canonicalName);
        });

        return roster;
    }

    function getLiveOperations(filterAgent) {
        const operations = [];
        for (const agentName of getAgentRoster()) {
            if (!matchesAgentFilter(agentName, filterAgent)) continue;
            const agent = ensureAgent(agentName);
            Object.values(agent.activeRuns).forEach(run => {
                operations.push({
                    key: operationKeyForRun(agentName, run),
                    type: 'live',
                    agent: agentName,
                    run,
                });
            });
        }
        return operations.sort((a, b) => sortByTimestampDesc(a.run, b.run));
    }

    function getRecentOperations(filterAgent) {
        const executions = [];
        for (const agentName of getAgentRoster()) {
            if (!matchesAgentFilter(agentName, filterAgent)) continue;
            const agent = ensureAgent(agentName);
            agent.executions.forEach(execution => executions.push(execution));
        }
        return executions.sort(sortExecutionDesc).slice(0, RECENT_OPERATION_LIMIT);
    }

    function resolveSelectedOperation(liveOperations, recentOperations) {
        if (!selectedOperationKey) return null;

        const liveMatch = liveOperations.find(op => op.key === selectedOperationKey);
        if (liveMatch) return { type: 'live', operation: liveMatch };

        const executionMatch = recentOperations.find(op => op.key === selectedOperationKey);
        if (executionMatch) return { type: 'execution', operation: executionMatch };

        selectedOperationKey = '';
        return null;
    }

    function matchesAgentFilter(agentName, filterAgent) {
        return filterAgent === ALL_AGENTS || HexAgentCatalog.canonicalAgentName(filterAgent) === agentName;
    }

    function normalizeExecution(execution, agentName) {
        const normalized = { ...execution, agent: agentName };
        normalized.key = operationKeyForExecution(normalized);
        return normalized;
    }

    function getExecutionPreview(execution, lineLimit) {
        const output = execution.raw_preview || execution.compacted_summary || '';
        if (!output) return '';
        const lines = output.split('\n');
        if (lines.length <= lineLimit) return output.trim();
        return `${lines.slice(0, lineLimit).join('\n').trim()}...`;
    }

    function getLatestExecution(agent) {
        if (!agent.executions.length) return null;
        return agent.executions.slice().sort(sortExecutionDesc)[0];
    }

    function getFailureCount(agent) {
        const historicalFailures = Math.max(
            Number(agent.stats.tool_runs || 0) - Number(agent.stats.successes || 0),
            agent.executions.filter(isExecutionFailure).length,
        );
        return historicalFailures;
    }

    function findLatestRun(agent, toolName) {
        const matches = Object.values(agent.activeRuns)
            .filter(run => !toolName || run.tool === toolName)
            .sort(sortByTimestampDesc);
        return matches.length ? matches[0].run_id : '';
    }

    function updateLiveOutputDom(run) {
        if (!container) return;
        const previewEl = container.querySelector(`[data-live-output="${cssEsc(run.run_id)}"]`);
        if (previewEl) {
            previewEl.textContent = tailLines(run.lines || [], LIVE_PREVIEW_LINES).join('\n') || 'Waiting for tool output...';
        }
        const detailEl = container.querySelector(`[data-detail-live-output="${cssEsc(run.run_id)}"]`);
        if (detailEl) {
            detailEl.textContent = (run.lines || []).join('\n');
            detailEl.scrollTop = detailEl.scrollHeight;
        }
    }

    function operationKeyForRun(agentName, run) {
        return `live:${HexAgentCatalog.canonicalAgentName(agentName)}:${run.run_id}`;
    }

    function operationKeyForExecution(execution) {
        const idPart = execution.id != null
            ? execution.id
            : [execution.run_id || '', execution.created_at || '', execution.tool_name || 'tool'].join(':');
        return `exec:${idPart}`;
    }

    function findExecutionById(execId) {
        const targetId = String(execId);
        for (const agent of Object.values(agents)) {
            const match = agent.executions.find(execution => String(execution.id || '') === targetId);
            if (match) return match;
        }
        return null;
    }

    function getOutcomeTone(execution) {
        const outcome = String(execution.outcome_kind || '').toLowerCase();
        if (isExecutionFailure(execution)) {
            if (outcome === 'partial_success') return 'warn';
            return 'fail';
        }
        if (execution.success == null && !outcome) return 'neutral';
        if (outcome === 'partial_success') return 'warn';
        return 'success';
    }

    function formatOutcomeLabel(execution) {
        const outcome = execution.outcome_kind || '';
        if (outcome) return outcome.replace(/_/g, ' ');
        if (execution.success === true || execution.success === 1) return 'success';
        if (isExecutionFailure(execution)) return 'failed';
        return 'completed';
    }

    function isExecutionFailure(execution) {
        return execution.success === 0 || execution.success === false;
    }

    function tailLines(lines, count) {
        return (lines || []).slice(-count);
    }

    function sortByTimestampDesc(a, b) {
        return String(b.started_at || b.created_at || '').localeCompare(String(a.started_at || a.created_at || ''));
    }

    function sortExecutionDesc(a, b) {
        return String(b.created_at || '').localeCompare(String(a.created_at || ''));
    }

    function formatDuration(seconds) {
        const sec = Number(seconds || 0);
        if (!Number.isFinite(sec) || sec <= 0) return '0s';
        if (sec < 60) return `${Math.round(sec)}s`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
        return `${Math.floor(sec / 3600)}h ${Math.round((sec % 3600) / 60)}m`;
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

    function escHtml(value) {
        if (value == null) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function cssEsc(value) {
        return String(value).replace(/"/g, '\\"');
    }

    return {
        init,
        setAgentStats,
        setActivityFeed,
        switchAgent(agentName) {
            selectedAgent = agentName ? HexAgentCatalog.canonicalAgentName(agentName) : ALL_AGENTS;
            selectedOperationKey = '';
            render();
        },
        writeExecution,
        writeToolStart,
        writeToolLine,
        writeToolComplete,
        writeMessage,
        clearAll,
        reset,
        fitAll,
        getAgentNames,
        getActiveAgent,
    };
})();
