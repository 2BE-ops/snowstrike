/**
 * SnowStrike AI v7 Dashboard — Main Application Controller (Canvas Redesign)
 *
 * Orchestrates: conversation stream, graph, artifacts, agents, terminals,
 * replay, view switching, drawer tabs, and stats.
 */

const HexApp = (() => {
    let mode = 'live';
    let eventSource = null;
    let clockInterval = null;
    let statsInterval = null;
    let lastExecCount = 0;

    // Phase definitions
    const PHASES = [
        'Reconnaissance', 'Enumeration', 'Vulnerability Analysis',
        'Exploitation', 'Post-Exploitation', 'Reporting',
    ];

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    async function init() {
        // Init sub-modules
        HexGraph.init();
        HexTerminals.init('terminalContent');
        HexArtifacts.init();
        HexAgents.init();
        HexAlerts.init();
        HexConversation.init();
        HexConversations.init();
        HexReplay.init();
        if (typeof HexTestingLab !== 'undefined') HexTestingLab.init();
        if (typeof HexExperiments !== 'undefined') HexExperiments.init();

        // Replay event handler
        HexReplay.setEventCallback(handleReplayEvent);

        // Mode toggle
        document.querySelectorAll('#modeToggle .mode-btn').forEach(btn => {
            btn.addEventListener('click', () => switchMode(btn.dataset.mode));
        });

        // View toggle (conversation / split / graph)
        document.querySelectorAll('#viewToggle .view-btn').forEach(btn => {
            btn.addEventListener('click', () => switchView(btn.dataset.view));
        });

        // Drawer tabs
        document.querySelectorAll('.drawer-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                document.querySelectorAll('#drawerContent > div').forEach(c => c.classList.remove('active'));
                const target = document.getElementById(`tab-${tabName}`);
                if (target) target.classList.add('active');

                // Load conversations on first click
                if (tabName === 'convos') HexConversations.load();
            });
        });

        // Artifact sub-tabs
        document.querySelectorAll('#tab-artifacts .tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const subtab = btn.dataset.subtab;
                document.querySelectorAll('#tab-artifacts .tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                document.querySelectorAll('#tab-artifacts .tab-content').forEach(c => c.classList.remove('active'));
                const target = document.getElementById(`subtab-${subtab}`);
                if (target) target.classList.add('active');
            });
        });

        // Node detail close
        document.getElementById('nodeDetailClose')?.addEventListener('click', () => {
            HexGraph.hideNodeDetail();
        });

        // Modal close
        document.getElementById('rawModalClose')?.addEventListener('click', closeModal);
        document.getElementById('rawModal')?.addEventListener('click', (e) => {
            if (e.target.id === 'rawModal') closeModal();
        });

        // Resize handle for drawer
        initResizeHandle();

        // Resize
        window.addEventListener('resize', () => HexTerminals.fitAll());

        // Initial data load
        await loadInitialData();

        // Start SSE + periodic stats
        connectSSE();
        statsInterval = setInterval(refreshStats, 8000);
    }

    // ------------------------------------------------------------------
    // View Switching
    // ------------------------------------------------------------------

    function switchView(view) {
        const canvas = document.getElementById('canvas');
        if (!canvas) return;
        canvas.setAttribute('data-view', view);

        document.querySelectorAll('#viewToggle .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === view);
        });

        // Refit graph and terminals after layout change
        requestAnimationFrame(() => {
            HexGraph.runLayout();
            HexTerminals.fitAll();
        });
    }

    // ------------------------------------------------------------------
    // Resize Handle (between graph and drawer)
    // ------------------------------------------------------------------

    function initResizeHandle() {
        const handle = document.getElementById('resizeHandle');
        const graphArea = document.querySelector('.graph-canvas-area');
        const drawer = document.getElementById('contextDrawer');
        if (!handle || !graphArea || !drawer) return;

        let startY, startGraphFlex, startDrawerFlex;

        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            startY = e.clientY;
            startGraphFlex = parseInt(getComputedStyle(graphArea).flexGrow) || 6;
            startDrawerFlex = parseInt(getComputedStyle(drawer).flexGrow) || 4;

            const onMove = (e) => {
                const delta = e.clientY - startY;
                const total = startGraphFlex + startDrawerFlex;
                const parentHeight = graphArea.parentElement.clientHeight;
                const ratio = delta / parentHeight * total;
                const newGraph = Math.max(2, Math.min(total - 2, startGraphFlex + ratio));
                const newDrawer = total - newGraph;
                graphArea.style.flex = newGraph;
                drawer.style.flex = newDrawer;
            };

            const onUp = () => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                HexTerminals.fitAll();
            };

            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    // ------------------------------------------------------------------
    // Initial Data Load
    // ------------------------------------------------------------------

    async function loadInitialData() {
        try {
            const [engRes, storyRes, planRes, netRes, hostsRes, vulnRes, credRes, lootRes, execRes, statsRes, actRes] =
                await Promise.allSettled([
                    fetch('/api/engagement').then(r => r.json()),
                    fetch('/api/story').then(r => r.json()),
                    fetch('/api/plan').then(r => r.json()),
                    fetch('/api/network-map').then(r => r.json()),
                    fetch('/api/hosts').then(r => r.json()),
                    fetch('/api/vulnerabilities').then(r => r.json()),
                    fetch('/api/credentials').then(r => r.json()),
                    fetch('/api/loot').then(r => r.json()),
                    fetch('/api/tool-executions').then(r => r.json()),
                    fetch('/api/stats').then(r => r.json()),
                    fetch('/api/agent-activity').then(r => r.json()),
                ]);

            // Header target
            if (engRes.status === 'fulfilled' && engRes.value.engagement) {
                const eng = engRes.value.engagement;
                const el = document.getElementById('headerTarget');
                if (el) el.textContent = `${eng.target || '\u2014'}`;
            }

            // Story -> Conversation stream
            if (storyRes.status === 'fulfilled') {
                HexConversation.updateStory(storyRes.value.story || '');
            }
            if (planRes.status === 'fulfilled') {
                HexConversation.updatePlan(planRes.value.plan);
            }

            // Artifacts
            if (vulnRes.status === 'fulfilled') HexArtifacts.updateVulns(vulnRes.value.vulnerabilities || []);
            if (credRes.status === 'fulfilled') HexArtifacts.updateCreds(credRes.value.credentials || []);
            if (lootRes.status === 'fulfilled') HexArtifacts.updateLoot(lootRes.value.loot || []);
            if (hostsRes.status === 'fulfilled') HexArtifacts.updateHosts(hostsRes.value.hosts || []);

            // Agent terminals from historical executions
            if (execRes.status === 'fulfilled') {
                const executions = execRes.value.executions || [];
                executions.forEach(ex => HexTerminals.writeExecution(ex.agent, ex));
                lastExecCount = executions.length;
            }

            // Stats bar
            if (statsRes.status === 'fulfilled') {
                updateStatsBar(statsRes.value);
            }

            // Cost display
            const engMatch = document.cookie.match(new RegExp('(^| )active_engagement=([^;]+)'));
            const engName = engMatch ? decodeURIComponent(engMatch[2]) : null;
            if (engName) {
                try {
                    const costRes = await fetch(`/api/engagement/${engName}/cost`).then(r => r.json());
                    updateCostDisplay(costRes);
                } catch (e) { /* cost endpoint may not exist */ }
            }

            // Load activity feed data BEFORE cards so cards can include it
            let agentStats = [];
            if (actRes.status === 'fulfilled') {
                const activity = actRes.value.activity || [];
                HexAgents.updateFeed(activity);
            }

            // Agent cards (now has activity data available)
            if (statsRes.status === 'fulfilled' && statsRes.value.agents) {
                agentStats = statsRes.value.agents;
                const sv = statsRes.value;
                HexAgents.updateCards(agentStats, {
                    phase: sv.current_phase,
                    completedPhases: sv.completed_phases,
                    agentTodos: sv.agent_todos || {},
                });
            }

            // Network graph
            if (netRes.status === 'fulfilled') {
                HexGraph.updateFromNetworkMap(netRes.value.network_map || {}, agentStats);
            }

            // Agent activity feed -> discovery edges + trails
            if (actRes.status === 'fulfilled') {
                const activity = actRes.value.activity || [];
                HexGraph.addAgentDiscoveryEdges(activity);
            }

        } catch (e) {
            console.error('Failed to load initial data:', e);
        }
    }

    // ------------------------------------------------------------------
    // Stats Bar (compact, in header + inline)
    // ------------------------------------------------------------------

    function updateStatsBar(stats) {
        if (!stats) return;

        // Header stats
        setStatText('statHosts', stats.hosts);
        setStatText('statServices', stats.services);
        setStatText('statCreds', stats.credentials);
        setStatText('statCritical', (stats.vulnerabilities || {}).critical);
        setStatText('statHigh', (stats.vulnerabilities || {}).high);
        setStatText('statMedium', (stats.vulnerabilities || {}).medium);
        setStatText('statLow', (stats.vulnerabilities || {}).low);

        // Inline stats
        const v = stats.vulnerabilities || {};
        setStatText('isHosts', stats.hosts);
        setStatText('isServices', stats.services);
        setStatText('isCreds', stats.credentials);
        setStatText('isTools', stats.tool_executions);
        setStatText('isCritical', v.critical);
        setStatText('isHigh', v.high);
        setStatText('isMedium', v.medium);
        setStatText('isLow', v.low);

        // Phase transition
        const currentPhase = stats.current_phase || '';
        HexConversation.checkPhaseTransition(currentPhase);

        // Autonomous run card
        updateAutoRunCard(stats);
        updateContextIndicator(stats.orchestrator_context || null);

        // Compaction state from context snapshot
        const ctxCompaction = (stats.orchestrator_context || {}).compaction;
        if (ctxCompaction) {
            HexConversation.updateCompactionUI(ctxCompaction);
        }
    }

    function setStatText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value ?? 0;
    }

    function updateCostDisplay(cost) {
        if (!cost) return;
        const costEl = document.getElementById('statCost');
        const tokEl = document.getElementById('statTokens');
        if (costEl) costEl.textContent = '$' + (cost.total_usd || 0).toFixed(2);
        if (tokEl) {
            const t = cost.total_tokens || 0;
            tokEl.textContent = t >= 1000000 ? (t / 1000000).toFixed(1) + 'M' :
                                t >= 1000 ? (t / 1000).toFixed(1) + 'K' : t;
        }
    }

    function updateContextIndicator(context) {
        const root = document.getElementById('contextStatus');
        const ring = document.getElementById('contextStatusRing');
        const percentEl = document.getElementById('contextStatusPercent');
        const modelEl = document.getElementById('contextStatusModel');
        if (!root || !ring || !percentEl || !modelEl) return;

        const percent = Number(context?.percent_used || 0);
        const ringPercent = Math.max(0, Math.min(100, percent));
        ring.style.setProperty('--context-angle', `${(ringPercent * 3.6).toFixed(1)}deg`);
        percentEl.textContent = `${Math.round(percent)}%`;
        modelEl.textContent = context?.model_label || context?.model || '—';

        // Provider badge (API vs CLI vs OpenAI vs Grok)
        const providerEl = document.getElementById('contextStatusProvider');
        if (providerEl) {
            const provider = context?.provider || '';
            if (provider) {
                const providerLabels = {
                    'anthropic': 'API',
                    'claude_code': 'CLI',
                    'openai': 'OpenAI',
                    'grok': 'Grok',
                };
                providerEl.textContent = providerLabels[provider] || provider;
                providerEl.dataset.provider = provider;
                providerEl.style.display = 'inline-block';
            } else {
                providerEl.style.display = 'none';
            }
        }

        let level = 'low';
        if (percent >= 90) level = 'critical';
        else if (percent >= 65) level = 'high';
        else if (percent >= 40) level = 'medium';
        root.dataset.level = level;

        if (context) {
            const promptTokens = Number(context.prompt_tokens || 0).toLocaleString();
            const rawWindow = Number(context.context_window || 0).toLocaleString();
            const usableWindow = Number(context.usable_window || 0).toLocaleString();
            const usablePercent = Number(context.usable_percent_used || 0).toFixed(1);
            root.title = `${percent.toFixed(1)}% of raw context window (${promptTokens} / ${rawWindow} tokens). ${usablePercent}% of usable budget (${usableWindow} tokens).`;
        } else {
            root.title = 'Estimated orchestrator context usage';
        }
    }

    // Autonomous run card
    let autoRunStartTime = null;
    let autoRunTimerInterval = null;

    function updateAutoRunCard(stats) {
        const card = document.getElementById('autoRunCard');
        if (!card) return;

        const run = stats.autonomous_run;
        if (!run) {
            card.classList.add('hidden');
            return;
        }

        card.classList.remove('hidden', 'completed', 'failed');
        const textEl = document.getElementById('autoRunText');
        const phaseEl = document.getElementById('autoRunPhase');
        const timerEl = document.getElementById('autoRunTimer');

        const phase = stats.current_phase || '';
        const completedCount = (stats.completed_phases || []).length;

        if (run.status === 'running') {
            textEl.textContent = 'Autonomous pentest running';
            phaseEl.textContent = phase ? `Phase: ${phase}` : '';
            if (run.started_at && !autoRunStartTime) {
                autoRunStartTime = run.started_at;
                if (!autoRunTimerInterval) {
                    autoRunTimerInterval = setInterval(() => {
                        if (autoRunStartTime) {
                            const elapsed = Math.floor(Date.now() / 1000 - autoRunStartTime);
                            const m = Math.floor(elapsed / 60);
                            const s = elapsed % 60;
                            timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
                        }
                    }, 1000);
                }
            }
        } else if (run.status === 'completed') {
            card.classList.add('completed');
            textEl.textContent = 'Autonomous pentest completed';
            phaseEl.textContent = `${completedCount} phases done`;
            clearInterval(autoRunTimerInterval);
            autoRunTimerInterval = null;
        } else if (run.status === 'failed') {
            card.classList.add('failed');
            textEl.textContent = 'Autonomous pentest failed';
            phaseEl.textContent = '';
            clearInterval(autoRunTimerInterval);
            autoRunTimerInterval = null;
        }
    }

    async function refreshStats() {
        if (mode !== 'live') return;
        try {
            const engMatch = document.cookie.match(new RegExp('(^| )active_engagement=([^;]+)'));
            const engName = engMatch ? decodeURIComponent(engMatch[2]) : null;
            const costUrl = engName ? `/api/engagement/${engName}/cost` : null;
            const fetches = [
                fetch('/api/stats').then(r => r.json()),
                fetch('/api/agent-activity?limit=50').then(r => r.json()),
            ];
            if (costUrl) fetches.push(fetch(costUrl).then(r => r.json()).catch(() => null));
            const [statsRes, actRes, costRes] = await Promise.all(fetches);
            updateStatsBar(statsRes);
            if (costRes) updateCostDisplay(costRes);

            // Update activity data first, then render cards (which include activity)
            const activity = actRes.activity || [];
            if (activity.length > 0 && activity.length !== lastExecCount) {
                HexAgents.updateFeed(activity);
                lastExecCount = activity.length;
            }

            if (statsRes.agents) HexAgents.updateCards(statsRes.agents, {
                phase: statsRes.current_phase,
                completedPhases: statsRes.completed_phases,
                agentTodos: statsRes.agent_todos || {},
            });
        } catch (e) {
            // silent
        }
    }

    // ------------------------------------------------------------------
    // SSE Connection (Live Mode)
    // ------------------------------------------------------------------

    let sseReconnectTimeout = null;
    let sseReconnectDelay = 1000;

    function unwrapEventPayload(raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && 'data' in parsed && 'source' in parsed && 'type' in parsed) {
            return {
                ...(parsed.data || {}),
                source: parsed.source,
                event_type: parsed.type,
                event_timestamp: parsed.timestamp,
                engagement_id: parsed.engagement_id,
            };
        }
        return parsed;
    }

    function connectSSE() {
        if (mode !== 'live') return;
        if (eventSource) { eventSource.close(); eventSource = null; }
        if (sseReconnectTimeout) { clearTimeout(sseReconnectTimeout); sseReconnectTimeout = null; }

        // v7.1: Try event-bus-driven endpoint first, fall back to polling-based
        eventSource = new EventSource('/api/events/live');

        eventSource.onopen = () => { sseReconnectDelay = 1000; };

        // Handle real-time event bus events
        eventSource.addEventListener('tool_output', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexTerminals.writeToolLine(payload.agent || payload.source || '', payload.tool, payload.line, payload);
            } catch {}
        });

        eventSource.addEventListener('tool_start', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexTerminals.writeToolStart(payload.agent || payload.source || '', payload);
                if (window.HexAvatars) HexAvatars.onToolStart(payload.agent || payload.source || '');
            } catch {}
        });

        eventSource.addEventListener('tool_complete', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexTerminals.writeToolComplete(payload.agent || payload.source || '', payload);
                if (window.HexAvatars) HexAvatars.onToolComplete(payload.agent || payload.source || '');
            } catch {}
        });

        eventSource.addEventListener('agent_start', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversation.appendDiscoveryEvent(
                    '🚀',
                    `${payload.agent || payload.source || 'Agent'} started: ${(payload.task || '').substring(0, 100)}`,
                    ''
                );
                if (window.HexAvatars) HexAvatars.onAgentStart(payload.agent || payload.source || '');
            } catch {}
        });

        eventSource.addEventListener('agent_complete', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                const icon = payload.success ? '✅' : '❌';
                HexConversation.appendDiscoveryEvent(
                    icon,
                    `${payload.agent || payload.source || 'Agent'} finished (${payload.duration}s)`,
                    ''
                );
                if (window.HexAvatars) HexAvatars.onAgentComplete(payload.agent || payload.source || '');
            } catch {}
        });

        eventSource.addEventListener('finding_discovered', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversation.appendDiscoveryEvent(
                    '🎯',
                    `[${String(payload.severity || 'info').toUpperCase()}] ${payload.title}`,
                    ''
                );
            } catch {}
        });

        eventSource.addEventListener('orchestrator_decision', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversation.appendDiscoveryEvent(
                    '🧠',
                    `Iteration ${payload.iteration}: ${payload.action} — ${(payload.reasoning || '').substring(0, 120)}`,
                    ''
                );
            } catch {}
        });

        eventSource.addEventListener('orchestrator_wave', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversation.appendDiscoveryEvent(
                    '⚡',
                    `Parallel dispatch: ${(payload.agents || []).join(', ')}`,
                    ''
                );
            } catch {}
        });

        eventSource.onerror = () => {
            if (eventSource) { eventSource.close(); eventSource = null; }
            if (mode === 'live') {
                sseReconnectTimeout = setTimeout(() => connectSSE(), sseReconnectDelay);
                sseReconnectDelay = Math.min(sseReconnectDelay * 2, 30000);
            }
        };

        eventSource.addEventListener('state_update', (e) => {
            if (mode !== 'live') return;
            try {
                const state = JSON.parse(e.data);
                const phase = state.current_phase || '';
                HexConversation.checkPhaseTransition(phase);
            } catch {}
        });

        eventSource.addEventListener('story_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexConversation.updateStory(data.story || '');
            } catch {}
        });

        eventSource.addEventListener('plan_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexConversation.updatePlan(data.plan);
            } catch {}
        });

        eventSource.addEventListener('network_update', (e) => {
            if (mode !== 'live') return;
            try {
                const networkMap = JSON.parse(e.data);
                HexGraph.updateFromNetworkMap(networkMap);
            } catch {}
        });

        eventSource.addEventListener('new_execution', (e) => {
            if (mode !== 'live') return;
            try {
                const exec = unwrapEventPayload(e.data);
                HexTerminals.writeExecution(exec.agent, exec);
                HexAgents.addExecution(exec);

                // Add discovery event in conversation stream
                const meta = HexConversation.getMeta(exec.agent);
                const icon = exec.success ? '\u2713' : '\u2717';
                const text = `${meta.short}: ${exec.tool_name}${exec.success ? '' : ' (failed)'}`;
                const time = HexConversation.formatTime(exec.created_at);
                HexConversation.appendDiscoveryEvent(
                    meta.icon, text, time,
                    null // could link to graph node if host IP known
                );
            } catch {}
        });

        eventSource.addEventListener('hosts_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexArtifacts.updateHosts(data.hosts || []);
                // Discovery event for new hosts
                (data.hosts || []).forEach(h => {
                    HexConversation.appendDiscoveryEvent(
                        '\u{1F5A5}',
                        `Host discovered: ${h.ip}${h.hostname ? ' (' + h.hostname + ')' : ''}`,
                        '',
                        'host_' + h.ip
                    );
                });
            } catch {}
        });

        eventSource.addEventListener('vulns_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexArtifacts.updateVulns(data.vulnerabilities || []);
            } catch {}
        });

        eventSource.addEventListener('creds_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexArtifacts.updateCreds(data.credentials || []);
            } catch {}
        });

        // Alerts from Kimi monitor
        eventSource.addEventListener('alerts_update', (e) => {
            if (mode !== 'live') return;
            try {
                const data = JSON.parse(e.data);
                HexAlerts.handleSSE(data);
            } catch {}
        });

        // Agent handoff events (new)
        eventSource.addEventListener('agent_handoff', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversation.appendHandoffCard(payload);
            } catch {}
        });

        // Live agent conversation turns (prompt streaming)
        eventSource.addEventListener('agent_turn', (e) => {
            if (mode !== 'live') return;
            try {
                const turn = unwrapEventPayload(e.data);
                HexConversations.appendLiveTurn(turn);
                if (window.HexAvatars && turn.agent) HexAvatars.onAgentTurn(turn.agent);
            } catch {}
        });

        eventSource.addEventListener('llm_start', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversations.startStreamingTurn(payload.source || '', payload.turn || 0, payload.model || '');
            } catch {}
        });

        eventSource.addEventListener('llm_token', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversations.appendStreamingToken(payload.source || '', payload.turn || 0, payload.token || '');
                if (window.HexAvatars) HexAvatars.onLLMToken(payload.source || '');
            } catch {}
        });

        eventSource.addEventListener('llm_complete', (e) => {
            if (mode !== 'live') return;
            try {
                const payload = unwrapEventPayload(e.data);
                HexConversations.completeStreamingTurn(payload.source || '', payload.turn || 0);
            } catch {}
        });

        eventSource.addEventListener('heartbeat', () => {});
    }

    function disconnectSSE() {
        if (sseReconnectTimeout) { clearTimeout(sseReconnectTimeout); sseReconnectTimeout = null; }
        if (eventSource) { eventSource.close(); eventSource = null; }
    }

    // ------------------------------------------------------------------
    // Mode Switching
    // ------------------------------------------------------------------

    async function switchMode(newMode) {
        if (mode === newMode) return;
        mode = newMode;

        document.querySelectorAll('#modeToggle .mode-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });

        const replayBar = document.getElementById('replayBar');
        HexTerminals.reset();

        if (mode === 'live') {
            replayBar?.classList.add('hidden');
            HexReplay.pause();
            connectSSE();
            await loadInitialData();
        } else {
            replayBar?.classList.remove('hidden');
            disconnectSSE();
            if (sseReconnectTimeout) { clearTimeout(sseReconnectTimeout); sseReconnectTimeout = null; }
            const count = await HexReplay.loadTimeline();
            if (count === 0) {
                HexConversation.appendAssistantMessage('*No events recorded yet. Run a phase first.*');
            }
        }
    }

    // ------------------------------------------------------------------
    // Replay Event Handler
    // ------------------------------------------------------------------

    function handleReplayEvent(msg) {
        if (msg.type === 'reset') {
            HexConversation.clear();
            HexTerminals.reset();
            HexArtifacts.updateVulns([]);
            HexArtifacts.updateCreds([]);
            HexArtifacts.updateLoot([]);
            HexArtifacts.updateHosts([]);
            return;
        }

        if (msg.type === 'event') {
            const evt = msg.event;
            switch (evt.event_type) {
                case 'host_discovered':
                    if (!msg.silent) {
                        HexConversation.appendDiscoveryEvent(
                            '\u{1F5A5}',
                            `Host discovered: ${evt.label}`,
                            fmtTime(evt.ts),
                            'host_' + (evt.label || '')
                        );
                    }
                    break;
                case 'tool_execution':
                    HexTerminals.writeExecution(evt.agent, {
                        tool_name: evt.label,
                        command: evt.label,
                        compacted_summary: evt.detail || '',
                        success: evt.success,
                        duration_seconds: 0,
                        created_at: evt.ts,
                    });
                    if (!msg.silent) {
                        const meta = HexConversation.getMeta(evt.agent);
                        const icon = evt.success ? '\u2713' : '\u2717';
                        HexConversation.appendDiscoveryEvent(
                            meta.icon,
                            `${meta.short}: ${evt.label}${evt.success ? '' : ' (failed)'}`,
                            fmtTime(evt.ts),
                            null
                        );
                    }
                    break;
                case 'vuln_found':
                    if (!msg.silent) {
                        const sev = (evt.detail || '').split(':')[0] || 'info';
                        HexConversation.appendDiscoveryEvent(
                            '\u26A0',
                            `Vulnerability: ${evt.label} (${sev})`,
                            fmtTime(evt.ts),
                            null
                        );
                    }
                    break;
                case 'credential_found':
                    if (!msg.silent) {
                        HexConversation.appendDiscoveryEvent(
                            '\u{1F511}',
                            `Credential found: ${evt.label}`,
                            fmtTime(evt.ts),
                            null
                        );
                    }
                    break;
            }
        }
    }

    // ------------------------------------------------------------------
    // Modal
    // ------------------------------------------------------------------

    function openModal(title, content) {
        const el = document.getElementById('rawModal');
        document.getElementById('rawModalTitle').textContent = title;
        document.getElementById('rawModalBody').textContent = content;
        el?.classList.remove('hidden');
    }

    function closeModal() {
        document.getElementById('rawModal')?.classList.add('hidden');
    }

    async function showRawLog(execId) {
        try {
            const resp = await fetch(`/api/tool-executions/${execId}/raw`);
            const data = await resp.json();
            openModal(`Raw Output #${execId}`, data.raw || '[empty]');
        } catch (e) {
            openModal('Error', `Failed to load raw log: ${e.message}`);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function fmtTime(ts) {
        if (!ts) return '--:--:--';
        try {
            const d = new Date(ts.includes('T') ? ts : ts + 'Z');
            return d.toLocaleTimeString('en-US', { hour12: false });
        } catch { return '--:--:--'; }
    }

    // ------------------------------------------------------------------
    // Boot
    // ------------------------------------------------------------------

    document.addEventListener('DOMContentLoaded', init);

    return { switchMode, openModal, closeModal, showRawLog };
})();


// ==================================================================
// HexSidebar — Right Drawer for engagement management
// ==================================================================
const HexSidebar = (() => {
    let sidebarEl, backdropEl, listEl, createPanelEl, createFormEl, createFeedbackEl, createToggleEl, createSubmitEl;

    function init() {
        sidebarEl = document.getElementById('sidebar');
        backdropEl = document.getElementById('sidebarBackdrop');
        listEl = document.getElementById('sidebarBody');
        createPanelEl = document.getElementById('sidebarCreatePanel');
        createFormEl = document.getElementById('sidebarCreateForm');
        createFeedbackEl = document.getElementById('sidebarCreateFeedback');
        createToggleEl = document.getElementById('sidebarNewEngagement');
        createSubmitEl = document.getElementById('sidebarCreateSubmit');

        document.getElementById('sidebarToggle')?.addEventListener('click', toggle);
        document.getElementById('sidebarClose')?.addEventListener('click', close);
        backdropEl?.addEventListener('click', close);
        createToggleEl?.addEventListener('click', () => toggleCreatePanel());
        createFormEl?.addEventListener('submit', handleCreateEngagement);
    }

    function toggle() {
        if (!sidebarEl) return;
        if (sidebarEl.classList.contains('visible')) { close(); } else { open(); }
    }

    function open() {
        sidebarEl?.classList.add('visible');
        sidebarEl?.classList.remove('hidden');
        backdropEl?.classList.remove('hidden');
        refreshList();
    }

    function close() {
        sidebarEl?.classList.remove('visible');
        setTimeout(() => {
            sidebarEl?.classList.add('hidden');
            backdropEl?.classList.add('hidden');
        }, 260);
    }

    async function refreshList() {
        if (!listEl) return;
        listEl.innerHTML = '<div class="placeholder">Loading...</div>';

        try {
            const resp = await fetch('/api/engagements');
            const data = await resp.json();
            const engagements = data.engagements || [];

            if (engagements.length === 0) {
                listEl.innerHTML = '<div class="placeholder">No engagements yet.</div>';
                return;
            }

            const groups = {};
            engagements.forEach(eng => {
                const g = eng.group_name || 'Default';
                (groups[g] = groups[g] || []).push(eng);
            });

            let html = '';
            const sortedGroups = Object.keys(groups).sort((a, b) => {
                if (a === 'Default') return 1;
                if (b === 'Default') return -1;
                return a.localeCompare(b);
            });

            for (const gName of sortedGroups) {
                html += `<div class="sidebar-group-title">${esc(gName)}</div>`;
                for (const eng of groups[gName]) {
                    const isActive = getActiveEngagement() === eng.name;
                    const tags = Array.isArray(eng.tags) ? eng.tags : [];
                    const tagHtml = tags.length
                        ? `<div class="sidebar-eng-tags">${tags.map(tag => `<span class="sidebar-tag">${esc(tag)}</span>`).join('')}</div>`
                        : '';
                    html += `<div class="sidebar-eng-item${isActive ? ' is-active' : ''}" data-eng="${esc(eng.name)}">
                        <div class="sidebar-eng-row">
                            <div class="sidebar-eng-info">
                                <div class="sidebar-eng-name">${esc(eng.name)}</div>
                                <div class="sidebar-eng-target">${esc(eng.target)}</div>
                            </div>
                            <button class="sidebar-eng-delete" data-eng="${esc(eng.name)}" title="Delete engagement">&times;</button>
                        </div>
                        ${tagHtml}
                    </div>`;
                }
            }

            // Clear all button at the bottom
            if (engagements.length > 0) {
                html += `<div class="sidebar-clear-all-wrap">
                    <button id="sidebarClearAll" class="sidebar-clear-all-btn">Clear All Data</button>
                </div>`;
            }

            listEl.innerHTML = html;

            // Click to select engagement
            listEl.querySelectorAll('.sidebar-eng-item').forEach(item => {
                item.addEventListener('click', (e) => {
                    // Don't select if clicking the delete button
                    if (e.target.closest('.sidebar-eng-delete')) return;
                    document.cookie = `active_engagement=${item.dataset.eng}; path=/; max-age=86400`;
                    window.location.reload();
                });
            });

            // Delete individual engagement
            listEl.querySelectorAll('.sidebar-eng-delete').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const engName = btn.dataset.eng;
                    if (!confirm(`Delete engagement "${engName}" and all its data? This cannot be undone.`)) return;
                    try {
                        const resp = await fetch(`/api/engagements/${encodeURIComponent(engName)}`, { method: 'DELETE' });
                        const data = await resp.json();
                        if (data.status === 'success') {
                            // If this was the active engagement, clear the cookie
                            if (getActiveEngagement() === engName) {
                                document.cookie = 'active_engagement=; path=/; max-age=0';
                            }
                            refreshList();
                        } else {
                            alert(data.detail || 'Failed to delete engagement');
                        }
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                });
            });

            // Clear all data
            const clearBtn = document.getElementById('sidebarClearAll');
            if (clearBtn) {
                clearBtn.addEventListener('click', async () => {
                    if (!confirm('Delete ALL engagements and their data? This cannot be undone.')) return;
                    try {
                        const resp = await fetch('/api/clear-all-data', { method: 'POST' });
                        const data = await resp.json();
                        if (data.status === 'success') {
                            document.cookie = 'active_engagement=; path=/; max-age=0';
                            window.location.reload();
                        } else {
                            alert(data.detail || 'Failed to clear data');
                        }
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                });
            }
        } catch (err) {
            listEl.innerHTML = `<div class="placeholder" style="color:var(--sev-critical)">Error: ${esc(err.message)}</div>`;
        }
    }

    function toggleCreatePanel(forceOpen) {
        if (!createPanelEl) return;
        const shouldOpen = typeof forceOpen === 'boolean'
            ? forceOpen
            : createPanelEl.classList.contains('hidden');

        createPanelEl.classList.toggle('hidden', !shouldOpen);
        createToggleEl?.classList.toggle('active', shouldOpen);

        if (!shouldOpen) { clearCreateFeedback(); return; }
        document.getElementById('sidebarNewTarget')?.focus();
    }

    function clearCreateFeedback() {
        if (!createFeedbackEl) return;
        createFeedbackEl.textContent = '';
        createFeedbackEl.classList.add('hidden');
        createFeedbackEl.classList.remove('error', 'success');
    }

    function setCreateFeedback(message, kind = 'error') {
        if (!createFeedbackEl) return;
        if (!message) { clearCreateFeedback(); return; }
        createFeedbackEl.textContent = message;
        createFeedbackEl.classList.remove('hidden', 'error', 'success');
        createFeedbackEl.classList.add(kind);
    }

    function setCreatePending(isPending) {
        if (createSubmitEl) {
            createSubmitEl.disabled = isPending;
            createSubmitEl.textContent = isPending ? 'Creating...' : 'Start Engagement';
        }
    }

    async function handleCreateEngagement(event) {
        event.preventDefault();
        const targetInput = document.getElementById('sidebarNewTarget');
        const nameInput = document.getElementById('sidebarNewName');
        const methodologyInput = document.getElementById('sidebarNewMethodology');
        const target = targetInput?.value.trim() || '';

        if (!target) {
            setCreateFeedback('Target is required.');
            targetInput?.focus();
            return;
        }

        setCreatePending(true);
        clearCreateFeedback();

        try {
            const resp = await fetch('/api/engagements', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target,
                    name: nameInput?.value.trim() || '',
                    methodology: methodologyInput?.value || 'standard',
                }),
            });
            const data = await resp.json();

            if (!data.engagement_name) {
                throw new Error(data.detail || 'Failed to create engagement');
            }

            document.cookie = `active_engagement=${data.engagement_name}; path=/; max-age=86400`;
            window.location.reload();
        } catch (err) {
            setCreateFeedback(err.message || 'Failed to create engagement');
        } finally {
            setCreatePending(false);
        }
    }

    function getActiveEngagement() {
        const m = document.cookie.match(new RegExp('(^| )active_engagement=([^;]+)'));
        return m ? decodeURIComponent(m[2]) : null;
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    document.addEventListener('DOMContentLoaded', init);
    return {};
})();
