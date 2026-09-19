/**
 * SnowStrike AI v7 — Unified Conversation Module
 *
 * Replaces the old chat.js, story.js, and parts of agents.js.
 * Renders a single chronological stream: user messages, orchestrator responses,
 * agent handoff cards, discovery events, and phase transitions.
 */

const HexConversation = (() => {
    let streamEl = null;
    let innerEl = null;
    let inputEl = null;
    let sendBtn = null;
    let placeholderEl = null;
    let planCardEl = null;
    let planBodyEl = null;
    let planMetaEl = null;
    let autoScroll = true;
    let isProcessing = false;
    let lastPhase = '';
    let compactionEnabled = false;
    let pendingFiles = [];  // Files staged for upload with next message

    // Agent metadata (kept in sync with HexAgents)
    const AGENT_META = {
        "Orchestrator":     { short: "Orchestrator", icon: "\u{1F9E0}", color: "var(--accent)" },
        "Recon Agent":      { short: "Recon",    icon: "\u{1F50D}", color: "var(--agent-recon)" },
        "WebApp Agent":     { short: "WebApp",   icon: "\u{1F310}", color: "var(--agent-webapp)" },
        "Attack Agent":     { short: "Attack",   icon: "\u2694\uFE0F", color: "var(--agent-attack, #C44A4A)" },
        "Cloud Agent":      { short: "Cloud",    icon: "\u2601",  color: "var(--agent-cloud)" },
        "BinaryRE Agent":   { short: "Binary",   icon: "\u2699",  color: "var(--agent-binary)" },
        "OSINT Agent":      { short: "OSINT",    icon: "\u{1F50E}", color: "var(--agent-osint)" },
        "Reporting Agent":  { short: "Report",   icon: "\u{1F4CB}", color: "var(--agent-reporting)" },
    };

    function getMeta(agentName) {
        return AGENT_META[agentName] || { short: agentName.replace(" Agent", ""), icon: "\u25C6", color: "var(--text-muted)" };
    }

    // Init marked
    if (typeof marked !== 'undefined') {
        marked.setOptions({ breaks: true, gfm: true, headerIds: false });
    }

    function init() {
        streamEl = document.getElementById('conversationStream');
        innerEl = document.getElementById('conversationInner');
        inputEl = document.getElementById('chatInput');
        sendBtn = document.getElementById('chatSend');
        placeholderEl = document.getElementById('conversationPlaceholder');
        planCardEl = document.getElementById('missionPlanCard');
        planBodyEl = document.getElementById('missionPlanBody');
        planMetaEl = document.getElementById('missionPlanMeta');

        if (!streamEl || !innerEl) return;

        // Auto-scroll detection
        streamEl.addEventListener('scroll', () => {
            const atBottom = streamEl.scrollHeight - streamEl.scrollTop - streamEl.clientHeight < 60;
            autoScroll = atBottom;
        });

        // Input handling
        if (inputEl) {
            inputEl.addEventListener('input', function () {
                this.style.height = 'auto';
                const newHeight = Math.min(this.scrollHeight, 140);
                this.style.height = newHeight + 'px';
                updateSendButton();
            });

            inputEl.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    if (!isProcessing && (inputEl.value.trim().length > 0 || pendingFiles.length > 0)) {
                        sendMessage();
                    }
                }
            });
        }

        if (sendBtn) {
            sendBtn.addEventListener('click', () => {
                if (!isProcessing && (inputEl.value.trim().length > 0 || pendingFiles.length > 0)) {
                    sendMessage();
                }
            });
        }

        // Action chips
        document.querySelectorAll('.action-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const action = chip.dataset.action;
                if (action === 'autonomous') {
                    inputEl.value = 'Run a full autonomous pentest against the target.';
                } else if (action === 'recon') {
                    inputEl.value = 'Run the reconnaissance phase.';
                } else if (action === 'report') {
                    inputEl.value = 'Generate a penetration testing report for all findings.';
                }
                inputEl.focus();
                inputEl.dispatchEvent(new Event('input'));
            });
        });

        // Compaction toggle
        const compactionSwitch = document.getElementById('compactionSwitch');
        if (compactionSwitch) {
            compactionSwitch.addEventListener('change', () => {
                toggleCompaction(compactionSwitch.checked);
            });
        }

        // File attachment (paperclip)
        const attachBtn = document.getElementById('chatAttachBtn');
        const fileInput = document.getElementById('chatFileInput');
        if (attachBtn && fileInput) {
            attachBtn.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', () => {
                addFilesToPending(fileInput.files);
                fileInput.value = '';  // Reset so same file can be re-added
            });
        }

        // Drag-and-drop on the chat input wrapper
        const inputWrapper = document.querySelector('.chat-input-wrapper');
        if (inputWrapper) {
            ['dragenter', 'dragover'].forEach(evt => {
                inputWrapper.addEventListener(evt, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    inputWrapper.classList.add('drag-over');
                });
            });
            ['dragleave', 'drop'].forEach(evt => {
                inputWrapper.addEventListener(evt, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    inputWrapper.classList.remove('drag-over');
                });
            });
            inputWrapper.addEventListener('drop', (e) => {
                if (e.dataTransfer?.files?.length) {
                    addFilesToPending(e.dataTransfer.files);
                }
            });
        }

        // Load chat history and compaction state
        loadHistory();
        loadCompactionState();
    }

    function updateSendButton() {
        if (!sendBtn || !inputEl) return;
        const hasText = inputEl.value.trim().length > 0;
        const hasFiles = pendingFiles.length > 0;
        if ((hasText || hasFiles) && !isProcessing) {
            sendBtn.removeAttribute('disabled');
        } else {
            sendBtn.setAttribute('disabled', 'true');
        }
    }

    function getActiveEngagement() {
        const match = document.cookie.match(new RegExp('(^| )active_engagement=([^;]+)'));
        if (match) return decodeURIComponent(match[2]);
        return null;
    }

    function scrollToBottom() {
        if (autoScroll && streamEl) {
            streamEl.scrollTop = streamEl.scrollHeight;
        }
    }

    function removePlaceholder() {
        if (placeholderEl) {
            placeholderEl.remove();
            placeholderEl = null;
        }
    }

    // ---------------------------------------------------------------
    // Message rendering
    // ---------------------------------------------------------------

    function appendUserMessage(text) {
        removePlaceholder();
        const msg = document.createElement('div');
        msg.className = 'msg user';
        msg.innerHTML = `<div class="msg-bubble">${escHtml(text)}</div>`;
        innerEl.appendChild(msg);
        scrollToBottom();
    }

    function appendAssistantMessage(text) {
        removePlaceholder();
        const msg = document.createElement('div');
        msg.className = 'msg assistant';
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        if (typeof marked !== 'undefined') {
            bubble.innerHTML = marked.parse(text);
        } else {
            bubble.textContent = text;
        }
        msg.appendChild(bubble);
        innerEl.appendChild(msg);
        scrollToBottom();
        return msg;
    }

    function createStreamingMessage() {
        removePlaceholder();
        const msg = document.createElement('div');
        msg.className = 'msg assistant';

        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        bubble.innerHTML = '<span class="streaming-cursor"></span>';

        msg.appendChild(bubble);
        innerEl.appendChild(msg);

        let accumulatedText = '';

        return {
            appendText(chunk) {
                accumulatedText += chunk;
                if (typeof marked !== 'undefined') {
                    bubble.innerHTML = marked.parse(accumulatedText) + '<span class="streaming-cursor"></span>';
                } else {
                    bubble.textContent = accumulatedText;
                }
                scrollToBottom();
            },
            showToolStatus(toolName, status) {
                const statusEl = document.createElement('div');
                statusEl.className = 'tool-status';
                if (status === 'executing') {
                    statusEl.innerHTML = `<span class="tool-spinner"></span> Running <code>${escHtml(toolName)}</code>...`;
                } else if (status === 'done') {
                    statusEl.innerHTML = `<span class="tool-check">\u2713</span> <code>${escHtml(toolName)}</code> complete`;
                }
                bubble.appendChild(statusEl);
                scrollToBottom();
            },
            finish() {
                if (typeof marked !== 'undefined') {
                    bubble.innerHTML = marked.parse(accumulatedText);
                } else {
                    bubble.textContent = accumulatedText;
                }
                bubble.querySelectorAll('.tool-status').forEach(el => el.remove());
                scrollToBottom();
            },
            getText() {
                return accumulatedText;
            }
        };
    }

    // ---------------------------------------------------------------
    // Agent Handoff Cards
    // ---------------------------------------------------------------

    function appendHandoffCard(data) {
        removePlaceholder();
        const targetName = data.agent || data.to || data.target || '';
        const sourceName = data.from || data.source || 'Orchestrator';
        const meta = getMeta(targetName);
        const fromMeta = getMeta(sourceName);
        const contextText = data.context || data.task || '';
        const resultText = data.result || data.summary || '';

        const card = document.createElement('div');
        card.className = 'handoff-card';
        card.style.setProperty('--agent-color', meta.color);
        card.setAttribute('data-agent-color', '');

        // Tools HTML
        let toolsHtml = '';
        if (data.tools && data.tools.length > 0) {
            toolsHtml = data.tools.map(t => {
                const statusCls = t.success ? 'success' : 'failed';
                const statusIcon = t.success ? '\u2713' : '\u2717';
                const dur = t.duration != null ? t.duration.toFixed(1) + 's' : '';
                return `<div class="handoff-tool-item" data-exec-id="${t.id || ''}">
                    <span class="handoff-tool-status ${statusCls}">${statusIcon}</span>
                    <span class="handoff-tool-name">${escHtml(t.tool_name || t.name || '')}</span>
                    <span class="handoff-tool-duration">${dur}</span>
                </div>`;
            }).join('');
        }

        const toolCount = (data.tools || []).length;
        const successCount = (data.tools || []).filter(t => t.success).length;
        const totalDuration = (data.tools || []).reduce((s, t) => s + (t.duration || 0), 0);

        card.innerHTML = `
            <div class="handoff-header">
                <span class="handoff-arrow">\u25B6</span>
                <span class="handoff-route">
                    <span class="handoff-from">${fromMeta.icon} ${escHtml(fromMeta.short)}</span>
                    \u2192
                    <span class="handoff-to">${meta.icon} ${escHtml(meta.short)}</span>
                </span>
                <span class="handoff-meta">
                    ${toolCount ? `${successCount}/${toolCount} tools` : ''}
                    ${totalDuration ? ` \u00B7 ${totalDuration.toFixed(1)}s` : ''}
                </span>
            </div>
            <div class="handoff-body">
                ${contextText ? `
                    <div class="handoff-section">
                        <div class="handoff-section-label">Context Passed</div>
                        <div class="handoff-context">${escHtml(contextText)}</div>
                    </div>
                ` : ''}
                ${toolsHtml ? `
                    <div class="handoff-section">
                        <div class="handoff-section-label">Tool Executions (${toolCount})</div>
                        <div class="handoff-tools">${toolsHtml}</div>
                    </div>
                ` : ''}
                ${resultText ? `
                    <div class="handoff-section">
                        <div class="handoff-section-label">Result Returned</div>
                        <div class="handoff-result">${escHtml(resultText)}</div>
                    </div>
                ` : ''}
                ${data.filename ? `
                    <div class="handoff-view-full" data-filename="${escHtml(data.filename)}">View full conversation</div>
                ` : ''}
            </div>
        `;

        // Toggle expand/collapse
        card.querySelector('.handoff-header').addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        // Tool item click -> raw log
        card.querySelectorAll('.handoff-tool-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = item.dataset.execId;
                if (id && window.HexApp && HexApp.showRawLog) {
                    HexApp.showRawLog(id);
                }
            });
        });

        // View full conversation link
        const viewFull = card.querySelector('.handoff-view-full');
        if (viewFull) {
            viewFull.addEventListener('click', (e) => {
                e.stopPropagation();
                // Switch to convos tab in drawer
                if (window.HexConversations) {
                    HexConversations.openByFilename(viewFull.dataset.filename);
                }
            });
        }

        innerEl.appendChild(card);
        scrollToBottom();
        return card;
    }

    // ---------------------------------------------------------------
    // Discovery Events (inline)
    // ---------------------------------------------------------------

    function appendDiscoveryEvent(icon, text, time, nodeId) {
        removePlaceholder();
        const el = document.createElement('div');
        el.className = 'discovery-event';
        el.innerHTML = `
            <span class="disc-icon">${icon}</span>
            <span class="disc-text">${escHtml(text)}</span>
            <span class="disc-time">${escHtml(time || '')}</span>
        `;
        if (nodeId) {
            el.dataset.nodeId = nodeId;
            el.addEventListener('click', () => {
                // Bidirectional link: click event -> highlight graph node
                if (window.HexGraph && HexGraph.highlightNode) {
                    HexGraph.highlightNode(nodeId);
                }
            });
        }
        innerEl.appendChild(el);
        scrollToBottom();
    }

    // ---------------------------------------------------------------
    // Phase Dividers
    // ---------------------------------------------------------------

    function appendPhaseDivider(fromPhase, toPhase) {
        removePlaceholder();
        const text = fromPhase ? `${fromPhase} \u2192 ${toPhase}` : toPhase;
        const el = document.createElement('div');
        el.className = 'phase-divider';
        el.textContent = text;
        innerEl.appendChild(el);
        scrollToBottom();
    }

    function checkPhaseTransition(newPhase) {
        if (newPhase && newPhase !== lastPhase) {
            appendPhaseDivider(lastPhase, newPhase);
            lastPhase = newPhase;
        }
    }

    // ---------------------------------------------------------------
    // Build handoff from tool execution data
    // ---------------------------------------------------------------

    /**
     * Convert a batch of tool executions for one agent into a handoff card.
     * Used when processing SSE new_execution events or loading historical data.
     */
    function buildHandoffFromExecutions(agent, executions) {
        const tools = executions.map(ex => ({
            id: ex.id,
            tool_name: ex.tool_name,
            name: ex.tool_name,
            success: ex.success,
            duration: ex.duration_seconds,
            summary: ex.compacted_summary,
        }));

        const successCount = tools.filter(t => t.success).length;
        const result = successCount > 0
            ? `${successCount}/${tools.length} tools completed successfully`
            : `${tools.length} tool(s) executed`;

        return appendHandoffCard({
            from: 'Orchestrator',
            agent: agent,
            to: agent,
            tools: tools,
            result: result,
            context: executions[0]?.command || '',
        });
    }

    // ---------------------------------------------------------------
    // File Attachments
    // ---------------------------------------------------------------

    function addFilesToPending(fileList) {
        for (const file of fileList) {
            if (pendingFiles.length >= 10) {
                appendAssistantMessage('Maximum 10 files per message.');
                break;
            }
            if (file.size > 50 * 1024 * 1024) {
                appendAssistantMessage(`File "${file.name}" exceeds 50 MB limit.`);
                continue;
            }
            pendingFiles.push(file);
        }
        renderAttachmentChips();
        updateSendButton();
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function renderAttachmentChips() {
        const container = document.getElementById('chatAttachments');
        if (!container) return;

        if (pendingFiles.length === 0) {
            container.style.display = 'none';
            container.innerHTML = '';
            return;
        }

        container.style.display = 'flex';
        container.innerHTML = pendingFiles.map((file, idx) => `
            <div class="chat-attachment-chip" data-idx="${idx}">
                <span class="attach-name" title="${escHtml(file.name)}">${escHtml(file.name)}</span>
                <span class="attach-size">${formatFileSize(file.size)}</span>
                <button class="attach-remove" data-idx="${idx}" title="Remove">&times;</button>
            </div>
        `).join('');

        container.querySelectorAll('.attach-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.idx);
                pendingFiles.splice(idx, 1);
                renderAttachmentChips();
                updateSendButton();
            });
        });
    }

    async function uploadFiles(engName, files) {
        if (!files.length) return [];

        const formData = new FormData();
        for (const file of files) {
            formData.append('files', file);
        }

        const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/upload`, {
            method: 'POST',
            body: formData,
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
            throw new Error(err.detail || 'File upload failed');
        }

        const data = await res.json();
        return data.uploaded || [];
    }

    // ---------------------------------------------------------------
    // Send Message
    // ---------------------------------------------------------------

    async function sendMessage() {
        const text = inputEl.value.trim();
        const hasFiles = pendingFiles.length > 0;
        if (!text && !hasFiles) return;

        const engName = getActiveEngagement();
        if (!engName) {
            appendAssistantMessage('No active engagement selected. Please select one from the sidebar.');
            return;
        }

        // Capture and clear pending files
        const filesToUpload = [...pendingFiles];
        pendingFiles = [];
        renderAttachmentChips();

        // Reset input
        inputEl.value = '';
        inputEl.style.height = 'auto';
        sendBtn.setAttribute('disabled', 'true');
        isProcessing = true;
        inputEl.setAttribute('disabled', 'true');

        // Build display text with attachment names
        let displayText = text || '';
        if (filesToUpload.length > 0) {
            const fileNames = filesToUpload.map(f => f.name).join(', ');
            if (displayText) {
                displayText += `\n\u{1F4CE} ${fileNames}`;
            } else {
                displayText = `\u{1F4CE} ${fileNames}`;
            }
        }
        appendUserMessage(displayText);

        try {
            // Upload files first if any
            let uploadedPaths = [];
            if (filesToUpload.length > 0) {
                try {
                    uploadedPaths = await uploadFiles(engName, filesToUpload);
                } catch (uploadErr) {
                    appendAssistantMessage(`File upload failed: ${uploadErr.message}`);
                    return;
                }
            }

            // Build message payload — include uploaded file paths so the orchestrator knows about them
            let messageText = text || '';
            if (uploadedPaths.length > 0) {
                const fileList = uploadedPaths.map(u => `- ${u.name} (${u.path}, ${formatFileSize(u.size)})`).join('\n');
                const fileCtx = `\n\n[Attached files uploaded to engagement loot directory]\n${fileList}`;
                messageText += fileCtx;
            }

            const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/chat/stream`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: messageText })
            });

            if (res.ok && res.headers.get('content-type')?.includes('text/event-stream')) {
                await handleStreamResponse(res);
            } else {
                await handleSyncResponse(engName, text);
            }
        } catch (e) {
            try {
                await handleSyncResponse(engName, text);
            } catch (e2) {
                appendAssistantMessage(`Connection error: ${e2.message}`);
            }
        } finally {
            isProcessing = false;
            inputEl.removeAttribute('disabled');
            inputEl.focus();
            updateSendButton();
        }
    }

    async function handleStreamResponse(res) {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        const streamMsg = createStreamingMessage();
        let buffer = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const payload = line.slice(6).trim();

                    if (payload === '[DONE]') {
                        streamMsg.finish();
                        return;
                    }

                    try {
                        const event = JSON.parse(payload);
                        switch (event.type) {
                            case 'text':
                                streamMsg.appendText(event.text);
                                break;
                            case 'tool_call':
                            case 'tool_executing':
                                streamMsg.showToolStatus(event.tool, 'executing');
                                break;
                            case 'tool_done':
                                streamMsg.showToolStatus(event.tool, 'done');
                                break;
                            case 'error':
                                streamMsg.appendText(`\n\n**Error:** ${event.text}`);
                                break;
                            case 'compaction':
                                appendCompactionNotice(event.info);
                                updateCompactionUI(event.info);
                                break;
                        }
                    } catch (parseErr) {
                        // skip malformed
                    }
                }
            }
        } finally {
            streamMsg.finish();
        }
    }

    async function handleSyncResponse(engName, text) {
        const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text })
        });

        if (res.ok) {
            const data = await res.json();
            appendAssistantMessage(data.response);
        } else {
            appendAssistantMessage(`Error: Server returned status ${res.status}`);
        }
    }

    // ---------------------------------------------------------------
    // Load History
    // ---------------------------------------------------------------

    async function loadHistory() {
        const engName = getActiveEngagement();
        if (!engName) return;

        try {
            const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/chat/history`);
            if (res.ok) {
                const data = await res.json();
                if (data.history && data.history.length > 0) {
                    removePlaceholder();
                    data.history.forEach(msg => {
                        if (msg.role === 'user') {
                            appendUserMessage(msg.content);
                        } else {
                            appendAssistantMessage(msg.content);
                        }
                    });
                    scrollToBottom();
                }
            }
        } catch (e) {
            console.error('Failed to load chat history', e);
        }
    }

    // ---------------------------------------------------------------
    // Story integration - update from SSE story_update events
    // ---------------------------------------------------------------
    let lastStoryContent = '';

    function updateStory(markdown) {
        if (!markdown || markdown === lastStoryContent) return;
        lastStoryContent = markdown;
    }

    function updatePlan(plan) {
        if (!planCardEl || !planBodyEl || !planMetaEl) return;

        if (!plan) {
            planCardEl.classList.add('hidden');
            planBodyEl.innerHTML = '';
            planMetaEl.textContent = '';
            return;
        }

        planCardEl.classList.remove('hidden');

        if (typeof plan === 'string') {
            planBodyEl.innerHTML = typeof marked !== 'undefined'
                ? marked.parse(plan)
                : escHtml(plan);
            planMetaEl.textContent = 'Markdown plan';
            return;
        }

        const objectives = Array.isArray(plan.objectives) ? plan.objectives : [];
        const phases = Array.isArray(plan.phases) ? plan.phases : [];
        const objectiveHtml = objectives.length
            ? objectives.map(obj => {
                const text = typeof obj === 'string' ? obj : (obj.description || '');
                const status = typeof obj === 'string' ? 'pending' : (obj.status || 'pending');
                return `<li class="mission-plan-item mission-plan-item-${escAttr(status)}">
                    <span class="mission-plan-check">${status === 'completed' ? '&#10003;' : '&#9675;'}</span>
                    <span>${escHtml(text)}</span>
                </li>`;
            }).join('')
            : '<li class="mission-plan-item"><span>No plan objectives yet.</span></li>';

        const nextTask = phases[0]?.waves?.[0]?.tasks?.[0];
        const nextTaskHtml = nextTask
            ? `<div class="mission-plan-next">
                <span class="mission-plan-next-label">Next Up</span>
                <span class="mission-plan-next-task">${escHtml(nextTask.agent || 'agent')} :: ${escHtml(nextTask.task || '')}</span>
            </div>`
            : '';

        planBodyEl.innerHTML = `
            <div class="mission-plan-summary">
                <span><strong>Target:</strong> ${escHtml(plan.target || 'unknown')}</span>
                <span><strong>Strategy:</strong> ${escHtml(plan.strategy || plan.methodology || 'dynamic')}</span>
            </div>
            ${nextTaskHtml}
            <ul class="mission-plan-list">${objectiveHtml}</ul>
        `;
        planMetaEl.textContent = `${objectives.length} objectives`;
    }

    // ---------------------------------------------------------------
    // Replay integration
    // ---------------------------------------------------------------

    function clear() {
        if (innerEl) {
            // Keep the inline-stats and auto-run card, clear everything else
            const stats = document.getElementById('inlineStats');
            const autoRun = document.getElementById('autoRunCard');
            const planCard = document.getElementById('missionPlanCard');
            innerEl.innerHTML = '';
            if (stats) innerEl.appendChild(stats);
            if (autoRun) innerEl.appendChild(autoRun);
            if (planCard) innerEl.appendChild(planCard);
        }
        lastPhase = '';
        lastStoryContent = '';
    }

    function appendReplayEvent(text) {
        removePlaceholder();
        const el = document.createElement('div');
        el.className = 'discovery-event';
        el.innerHTML = `<span class="disc-text" style="font-size:12px;">${text}</span>`;
        innerEl.appendChild(el);
        if (autoScroll) scrollToBottom();
    }

    // ---------------------------------------------------------------
    // Context Compaction
    // ---------------------------------------------------------------

    async function loadCompactionState() {
        const engName = getActiveEngagement();
        if (!engName) return;
        try {
            const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/compaction`);
            if (res.ok) {
                const info = await res.json();
                updateCompactionUI(info);
            }
        } catch (e) {
            console.error('Failed to load compaction state', e);
        }
    }

    async function toggleCompaction(enabled) {
        const engName = getActiveEngagement();
        if (!engName) return;
        try {
            const res = await fetch(`/api/engagement/${encodeURIComponent(engName)}/compaction`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
            });
            if (res.ok) {
                const info = await res.json();
                updateCompactionUI(info);
            }
        } catch (e) {
            console.error('Failed to toggle compaction', e);
        }
    }

    function updateCompactionUI(info) {
        if (!info) return;
        compactionEnabled = info.enabled;

        const toggle = document.getElementById('compactionSwitch');
        if (toggle) toggle.checked = info.enabled;

        const statusEl = document.getElementById('compactionStatus');
        if (!statusEl) return;

        if (!info.enabled) {
            statusEl.textContent = '';
            statusEl.title = '';
            return;
        }

        if (info.compaction_count > 0) {
            statusEl.textContent = `${info.compaction_count}×`;
            const ts = info.last_compacted_at
                ? new Date(info.last_compacted_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
                : '—';
            statusEl.title = `Compacted ${info.compaction_count} time(s), last at ${ts}`;
        } else {
            statusEl.textContent = 'On';
            statusEl.title = 'Compaction enabled, will activate when context is large';
        }
    }

    function appendCompactionNotice(info) {
        removePlaceholder();
        const el = document.createElement('div');
        el.className = 'compaction-notice';
        const count = info?.compaction_count || '?';
        el.innerHTML = `<span class="compaction-notice-icon">&#x2696;</span> Context compacted (${count}× total)`;
        innerEl.appendChild(el);
        scrollToBottom();
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    function escHtml(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escAttr(s) {
        return escHtml(s).replace(/\s+/g, '-').toLowerCase();
    }

    function formatTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch { return ''; }
    }

    return {
        init,
        appendUserMessage,
        appendAssistantMessage,
        appendHandoffCard,
        appendDiscoveryEvent,
        appendPhaseDivider,
        checkPhaseTransition,
        buildHandoffFromExecutions,
        createStreamingMessage,
        updateStory,
        updatePlan,
        clear,
        appendReplayEvent,
        formatTime,
        getMeta,
        AGENT_META,
        updateCompactionUI,
        loadCompactionState,
    };
})();
