/**
 * SnowStrike AI v7.0 - Settings Panel
 *
 * Tabs: Models | Prompts | Master Profiles | History & Costs
 */

(function () {
    /* ── DOM refs ── */
    const panel       = document.getElementById('settingsPanel');
    const form        = document.getElementById('modelConfigForm');
    const rowsC       = document.getElementById('modelRoleRows');
    const toggleBtn   = document.getElementById('settingsToggle');
    const closeBtn    = document.getElementById('settingsClose');
    const resetBtn    = document.getElementById('settingsReset');
    const subtitle    = document.getElementById('spSubtitle');

    /* ── State ── */
    let availableModels   = [];
    let configurableRoles = [];
    let globalDefaults    = {};
    let currentConfig     = {};
    let modelConfigs      = [];
    let promptProfiles    = [];
    let masterProfiles    = [];
    let activeMasterProfile = null;
    let profileHistory    = [];

    // Prompt editor state
    let editingPromptProfile = null;
    let editingAgentType     = null;
    let promptEditorDirty    = false;

    /* ── Helpers ── */
    function getEngName() {
        const m = document.cookie.match(/(?:^|;\s*)active_engagement=([^;]*)/);
        return m ? decodeURIComponent(m[1]) : null;
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s || '');
        return d.innerHTML;
    }

    function formatUsd(value) {
        return new Intl.NumberFormat('en-US', {
            style: 'currency', currency: 'USD',
            minimumFractionDigits: 2, maximumFractionDigits: 4,
        }).format(Number(value || 0));
    }

    function formatDuration(seconds) {
        if (!seconds) return '—';
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${(seconds / 3600).toFixed(1)}h`;
    }

    /* ════════════════════════════════════════════════════
     *  TAB SWITCHING
     * ════════════════════════════════════════════════════ */

    const tabLabels = { models: 'Models', prompts: 'Prompts', master: 'Master Profiles', history: 'History & Costs' };

    document.getElementById('spTabs').addEventListener('click', (e) => {
        const btn = e.target.closest('.sp-tab');
        if (!btn) return;
        const tab = btn.dataset.tab;
        document.querySelectorAll('.sp-tab').forEach(t => t.classList.toggle('active', t === btn));
        document.querySelectorAll('.sp-pane').forEach(p => p.classList.toggle('active', p.id === `sp-${tab}`));
        subtitle.textContent = tabLabels[tab] || '';

        // Lazy-load tab data
        if (tab === 'prompts') loadAndRenderPrompts();
        if (tab === 'master') loadAndRenderMaster();
        if (tab === 'history') loadAndRenderHistory();
    });

    /* ════════════════════════════════════════════════════
     *  DATA LOADING
     * ════════════════════════════════════════════════════ */

    async function loadAvailableModels() {
        try {
            const r = await fetch('/api/available-models');
            const d = await r.json();
            availableModels   = d.models || [];
            configurableRoles = d.roles  || [];
            globalDefaults    = d.defaults || {};
        } catch (e) { console.error('Failed to load models:', e); }
    }

    async function loadCurrentConfig() {
        const eng = getEngName();
        if (!eng) return;
        try {
            const r = await fetch(`/api/engagement/${encodeURIComponent(eng)}/model-config`);
            const d = await r.json();
            currentConfig = d.model_config || {};
        } catch (e) { currentConfig = {}; }
    }

    async function loadModelConfigs() {
        try {
            const r = await fetch('/api/testing/model-configs');
            const d = await r.json();
            modelConfigs = d.configs || [];
        } catch (e) { modelConfigs = []; }
    }

    async function loadPromptProfiles() {
        try {
            const r = await fetch('/api/settings/prompt-profiles');
            const d = await r.json();
            promptProfiles = d.profiles || [];
        } catch (e) { promptProfiles = []; }
    }

    async function loadMasterProfiles() {
        try {
            const r = await fetch('/api/settings/master-profiles');
            const d = await r.json();
            masterProfiles = d.profiles || [];
        } catch (e) { masterProfiles = []; }
    }

    async function loadActiveMasterProfile() {
        const eng = getEngName();
        if (!eng) { activeMasterProfile = null; return; }
        try {
            const r = await fetch(`/api/engagement/${encodeURIComponent(eng)}/master-profile`);
            const d = await r.json();
            activeMasterProfile = d.master_profile || null;
        } catch (e) { activeMasterProfile = null; }
    }

    async function loadProfileHistory() {
        try {
            const r = await fetch('/api/settings/profile-history');
            const d = await r.json();
            profileHistory = d.profiles || [];
        } catch (e) { profileHistory = []; }
    }

    /* ════════════════════════════════════════════════════
     *  MODELS TAB — Per-Role Assignment
     * ════════════════════════════════════════════════════ */

    function resolveDefault(roleKey) {
        if (roleKey === 'orchestrator' || roleKey === 'planning')
            return globalDefaults[roleKey] || globalDefaults.sub_agent || '';
        return globalDefaults.sub_agent || '';
    }

    function renderModelForm() {
        rowsC.innerHTML = '';
        configurableRoles.forEach(role => {
            const row = document.createElement('div');
            row.className = 'sp-role-row';
            const label = document.createElement('label');
            label.className = 'sp-role-label';
            label.textContent = role.label;
            const select = document.createElement('select');
            select.name = role.key;
            select.className = 'sp-select';
            const defId    = resolveDefault(role.key);
            const defModel = availableModels.find(m => m.id === defId);
            const defLabel = defModel ? defModel.label : defId;
            const defOpt = document.createElement('option');
            defOpt.value = '';
            defOpt.textContent = `Default (${defLabel})`;
            select.appendChild(defOpt);
            availableModels.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m.id;
                opt.textContent = `${m.label}  [${m.provider}]`;
                if (currentConfig[role.key] === m.id) opt.selected = true;
                select.appendChild(opt);
            });
            row.appendChild(label);
            row.appendChild(select);
            rowsC.appendChild(row);
        });
    }

    function applyModelConfig(roles) {
        configurableRoles.forEach(role => {
            const sel = form.querySelector(`select[name="${role.key}"]`);
            if (!sel) return;
            const val = roles[role.key] || '';
            const opts = Array.from(sel.options);
            const match = opts.find(o => o.value === val);
            sel.value = match ? val : '';
        });
    }

    function readFormRoles() {
        const roles = {};
        configurableRoles.forEach(role => {
            const sel = form.querySelector(`select[name="${role.key}"]`);
            if (sel && sel.value) roles[role.key] = sel.value;
        });
        return roles;
    }

    async function saveEngagementConfig(e) {
        e.preventDefault();
        const eng = getEngName();
        if (!eng) return;
        const config = readFormRoles();
        const btn = form.querySelector('button[type="submit"]');
        const orig = btn.textContent;
        btn.textContent = 'Saving...'; btn.disabled = true;
        try {
            const r = await fetch(`/api/engagement/${encodeURIComponent(eng)}/model-config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ models: config }),
            });
            const d = await r.json();
            if (d.status === 'success') {
                currentConfig = d.model_config || {};
                showToast('Model config saved');
            } else {
                showToast('Error: ' + (d.detail || 'Failed'), true);
            }
        } catch (err) {
            showToast('Error: ' + err.message, true);
        } finally {
            btn.textContent = orig; btn.disabled = false;
        }
    }

    function resetAll() { form.querySelectorAll('select').forEach(s => { s.value = ''; }); }

    /* ════════════════════════════════════════════════════
     *  MODELS TAB — Saved Model Configs
     * ════════════════════════════════════════════════════ */

    function renderModelProfiles() {
        const c = document.getElementById('spModelProfilesList');
        if (!modelConfigs.length) {
            c.innerHTML = '<div class="sp-empty">No model configs saved yet.</div>';
            return;
        }
        let html = '';
        modelConfigs.forEach(cfg => {
            const tags = (cfg.tags || []).map(t => `<span class="sp-tag">${esc(t)}</span>`).join('');
            const roleRows = Object.entries(cfg.roles || {}).map(([k, v]) =>
                `<span class="sp-role-chip"><b>${esc(k)}</b> ${esc(v)}</span>`
            ).join('');
            html += `
            <div class="sp-card" data-config="${esc(cfg.name)}">
                <div class="sp-card-header">
                    <span class="sp-card-name">${esc(cfg.name)}</span>
                    <div class="sp-card-actions">
                        <button class="sp-card-btn sp-load-config" title="Load into form">Load</button>
                        <button class="sp-card-btn sp-card-delete" data-type="model-config" data-name="${esc(cfg.name)}" title="Delete">&times;</button>
                    </div>
                </div>
                <div class="sp-card-desc">${esc(cfg.description || '')}</div>
                <div class="sp-card-tags">${tags}</div>
                <div class="sp-role-chips">${roleRows}</div>
            </div>`;
        });
        c.innerHTML = html;

        c.querySelectorAll('.sp-load-config').forEach(btn => {
            btn.addEventListener('click', () => {
                const card = btn.closest('.sp-card');
                const name = card.dataset.config;
                const cfg = modelConfigs.find(c => c.name === name);
                if (cfg) { applyModelConfig(cfg.roles || {}); showToast(`Loaded "${name}" into form`); }
            });
        });
        c.querySelectorAll('.sp-card-delete').forEach(btn => {
            btn.addEventListener('click', async () => {
                const name = btn.dataset.name;
                if (!confirm(`Delete model config "${name}"?`)) return;
                try {
                    await fetch(`/api/settings/model-configs/${encodeURIComponent(name)}`, { method: 'DELETE' });
                    await loadModelConfigs();
                    renderModelProfiles();
                    showToast(`Deleted "${name}"`);
                } catch (e) { showToast('Delete failed', true); }
            });
        });
    }

    function setupModelProfileForm() {
        const formEl    = document.getElementById('spModelProfileForm');
        const newBtn    = document.getElementById('spNewModelProfile');
        const cancelBtn = document.getElementById('spCancelModelProfile');
        const saveBtn   = document.getElementById('spSaveModelProfile');

        newBtn.addEventListener('click', () => formEl.classList.toggle('hidden'));
        cancelBtn.addEventListener('click', () => formEl.classList.add('hidden'));
        saveBtn.addEventListener('click', async () => {
            const name = document.getElementById('spNewModelName').value.trim();
            const desc = document.getElementById('spNewModelDesc').value.trim();
            if (!name) { showToast('Name required', true); return; }
            const roles = readFormRoles();
            if (!Object.keys(roles).length) { showToast('Select at least one model above', true); return; }
            saveBtn.disabled = true;
            try {
                const r = await fetch('/api/testing/model-configs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, roles, description: desc }),
                });
                const d = await r.json();
                if (d.success) {
                    formEl.classList.add('hidden');
                    document.getElementById('spNewModelName').value = '';
                    document.getElementById('spNewModelDesc').value = '';
                    await loadModelConfigs();
                    renderModelProfiles();
                    showToast(`Created model config "${name}"`);
                } else { showToast(d.detail || 'Error', true); }
            } catch (e) { showToast('Save failed: ' + e.message, true); }
            finally { saveBtn.disabled = false; }
        });
    }

    /* ════════════════════════════════════════════════════
     *  PROMPTS TAB
     * ════════════════════════════════════════════════════ */

    async function loadAndRenderPrompts() {
        await loadPromptProfiles();
        renderPromptProfiles();
    }

    function renderPromptProfiles() {
        const c = document.getElementById('spPromptProfilesList');
        if (!promptProfiles.length) {
            c.innerHTML = '<div class="sp-empty">No prompt profiles yet.</div>';
            return;
        }
        let html = '';
        promptProfiles.forEach(p => {
            const tags = (p.tags || []).map(t => `<span class="sp-tag">${esc(t)}</span>`).join('');
            const prompts = (p.prompts || []).map(name => `<span class="sp-role-chip">${esc(name)}</span>`).join('');
            const isDefault = p.name === 'default';
            html += `
            <div class="sp-card" data-profile="${esc(p.name)}">
                <div class="sp-card-header">
                    <span class="sp-card-name">${esc(p.name)}${isDefault ? ' <span class="sp-badge">default</span>' : ''}</span>
                    <div class="sp-card-actions">
                        <button class="sp-card-btn sp-edit-prompts" data-name="${esc(p.name)}" title="Edit prompts">Edit</button>
                        <button class="sp-card-btn sp-dup-prompt" data-name="${esc(p.name)}" title="Duplicate">Dup</button>
                        ${isDefault ? '' : `<button class="sp-card-btn sp-card-delete sp-del-prompt" data-name="${esc(p.name)}" title="Delete">&times;</button>`}
                    </div>
                </div>
                <div class="sp-card-desc">${esc(p.description || '')}</div>
                <div class="sp-card-tags">${tags}</div>
                <div class="sp-card-meta">${p.prompt_count || 0} prompts</div>
                <div class="sp-role-chips">${prompts}</div>
            </div>`;
        });
        c.innerHTML = html;

        // Edit buttons
        c.querySelectorAll('.sp-edit-prompts').forEach(btn => {
            btn.addEventListener('click', () => openPromptEditor(btn.dataset.name));
        });
        // Duplicate
        c.querySelectorAll('.sp-dup-prompt').forEach(btn => {
            btn.addEventListener('click', async () => {
                const name = btn.dataset.name;
                const newName = prompt(`Duplicate "${name}" as:`, `${name}-copy`);
                if (!newName) return;
                try {
                    const r = await fetch(`/api/settings/prompt-profiles/${encodeURIComponent(name)}/duplicate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ new_name: newName }),
                    });
                    const d = await r.json();
                    if (d.success) { await loadAndRenderPrompts(); showToast(`Duplicated as "${newName}"`); }
                    else showToast(d.detail || 'Error', true);
                } catch (e) { showToast('Failed: ' + e.message, true); }
            });
        });
        // Delete
        c.querySelectorAll('.sp-del-prompt').forEach(btn => {
            btn.addEventListener('click', async () => {
                const name = btn.dataset.name;
                if (!confirm(`Delete prompt profile "${name}"?`)) return;
                try {
                    await fetch(`/api/settings/prompt-profiles/${encodeURIComponent(name)}`, { method: 'DELETE' });
                    await loadAndRenderPrompts();
                    showToast(`Deleted "${name}"`);
                } catch (e) { showToast('Delete failed', true); }
            });
        });
    }

    // New prompt profile form
    function setupPromptProfileForm() {
        const formEl    = document.getElementById('spNewPromptForm');
        const newBtn    = document.getElementById('spNewPromptProfile');
        const cancelBtn = document.getElementById('spCancelPromptProfile');
        const saveBtn   = document.getElementById('spSavePromptProfile');

        newBtn.addEventListener('click', async () => {
            // Populate source dropdown
            if (!promptProfiles.length) await loadPromptProfiles();
            const sel = document.getElementById('spNewPromptSource');
            sel.innerHTML = '<option value="default">Default prompts</option>';
            promptProfiles.forEach(p => {
                if (p.name === 'default') return;
                sel.innerHTML += `<option value="${esc(p.name)}">${esc(p.name)}</option>`;
            });
            formEl.classList.toggle('hidden');
        });
        cancelBtn.addEventListener('click', () => formEl.classList.add('hidden'));
        saveBtn.addEventListener('click', async () => {
            const name = document.getElementById('spNewPromptName').value.trim();
            const source = document.getElementById('spNewPromptSource').value;
            const desc = document.getElementById('spNewPromptDesc').value.trim();
            if (!name) { showToast('Name required', true); return; }
            saveBtn.disabled = true;
            try {
                const r = await fetch('/api/settings/prompt-profiles', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, source, description: desc }),
                });
                const d = await r.json();
                if (d.success) {
                    formEl.classList.add('hidden');
                    document.getElementById('spNewPromptName').value = '';
                    document.getElementById('spNewPromptDesc').value = '';
                    await loadAndRenderPrompts();
                    showToast(`Created prompt profile "${name}"`);
                } else { showToast(d.detail || 'Error', true); }
            } catch (e) { showToast('Failed: ' + e.message, true); }
            finally { saveBtn.disabled = false; }
        });
    }

    /* ── Prompt Editor ── */

    const AGENT_ROLES = [
        'orchestrator', 'recon', 'webapp', 'browser', 'attack',
        'cloud', 'binary', 'forensics', 'osint', 'reporting',
    ];

    async function openPromptEditor(profileName) {
        editingPromptProfile = profileName;
        const editor = document.getElementById('spPromptEditor');
        const title  = document.getElementById('spPromptEditorTitle');
        const desc   = document.getElementById('spPromptEditorDesc');
        title.textContent = `Editing: ${profileName}`;
        desc.textContent = 'Select an agent role to edit its system prompt.';
        editor.classList.remove('hidden');

        // Build agent tabs
        const tabsC = document.getElementById('spPromptAgentTabs');
        tabsC.innerHTML = AGENT_ROLES.map(role =>
            `<button class="sp-prompt-tab" data-role="${role}">${role}</button>`
        ).join('');

        tabsC.querySelectorAll('.sp-prompt-tab').forEach(btn => {
            btn.addEventListener('click', () => loadAgentPrompt(profileName, btn.dataset.role));
        });

        // Auto-select first
        loadAgentPrompt(profileName, AGENT_ROLES[0]);
    }

    async function loadAgentPrompt(profileName, agentType) {
        editingAgentType = agentType;
        promptEditorDirty = false;

        // Highlight active tab
        document.querySelectorAll('.sp-prompt-tab').forEach(t =>
            t.classList.toggle('active', t.dataset.role === agentType)
        );

        const area = document.getElementById('spPromptEditorArea');
        area.value = 'Loading...';
        try {
            const r = await fetch(`/api/settings/prompt-profiles/${encodeURIComponent(profileName)}/agent/${agentType}`);
            if (r.ok) {
                const d = await r.json();
                area.value = d.content || '';
            } else {
                area.value = `(No prompt found for ${agentType} in this profile)`;
            }
        } catch (e) {
            area.value = `Error loading: ${e.message}`;
        }
    }

    function setupPromptEditor() {
        const area = document.getElementById('spPromptEditorArea');
        area.addEventListener('input', () => { promptEditorDirty = true; });

        document.getElementById('spPromptEditorSave').addEventListener('click', async () => {
            if (!editingPromptProfile || !editingAgentType) return;
            const content = area.value;
            try {
                const r = await fetch(`/api/settings/prompt-profiles/${encodeURIComponent(editingPromptProfile)}/agent/${editingAgentType}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content }),
                });
                const d = await r.json();
                if (d.success) {
                    promptEditorDirty = false;
                    showToast(`Saved ${editingAgentType} prompt`);
                } else { showToast(d.detail || 'Save failed', true); }
            } catch (e) { showToast('Save failed: ' + e.message, true); }
        });

        document.getElementById('spPromptEditorClose').addEventListener('click', () => {
            if (promptEditorDirty && !confirm('Unsaved changes. Close anyway?')) return;
            document.getElementById('spPromptEditor').classList.add('hidden');
            editingPromptProfile = null;
            editingAgentType = null;
        });
    }

    /* ════════════════════════════════════════════════════
     *  MASTER PROFILES TAB
     * ════════════════════════════════════════════════════ */

    async function loadAndRenderMaster() {
        await Promise.all([loadMasterProfiles(), loadModelConfigs(), loadPromptProfiles(), loadActiveMasterProfile()]);
        renderMasterProfiles();
    }

    function renderMasterProfiles() {
        const c = document.getElementById('spMasterProfilesList');
        const activeBadge = document.getElementById('spActiveMasterProfile');

        // Show active master profile badge
        if (activeMasterProfile) {
            activeBadge.innerHTML = `<span class="sp-active-label">Active:</span> <b>${esc(activeMasterProfile)}</b>`;
            activeBadge.classList.remove('hidden');
        } else {
            activeBadge.classList.add('hidden');
        }

        if (!masterProfiles.length) {
            c.innerHTML = '<div class="sp-empty">No master profiles yet. Create one to combine models + prompts.</div>';
            return;
        }

        let html = '';
        masterProfiles.forEach(mp => {
            const isActive = mp.name === activeMasterProfile;
            const tags = (mp.tags || []).map(t => `<span class="sp-tag">${esc(t)}</span>`).join('');
            const overrideKeys = Object.keys(mp.agent_overrides || {});
            const overrideInfo = overrideKeys.length ? `<span class="sp-role-chip"><b>Overrides:</b> ${esc(overrideKeys.join(', '))}</span>` : '';
            html += `
            <div class="sp-card ${isActive ? 'sp-card-active' : ''}" data-master="${esc(mp.name)}">
                <div class="sp-card-header">
                    <span class="sp-card-name">${esc(mp.name)}${isActive ? ' <span class="sp-badge sp-badge-active">ACTIVE</span>' : ''}</span>
                    <div class="sp-card-actions">
                        ${isActive ? '' : `<button class="sp-card-btn sp-activate-master" data-name="${esc(mp.name)}" title="Activate for engagement">Activate</button>`}
                        <button class="sp-card-btn sp-card-delete sp-del-master" data-name="${esc(mp.name)}" title="Delete">&times;</button>
                    </div>
                </div>
                <div class="sp-card-desc">${esc(mp.description || '')}</div>
                <div class="sp-card-tags">${tags}</div>
                <div class="sp-role-chips">
                    <span class="sp-role-chip"><b>Models:</b> ${esc(mp.model_config || '—')}</span>
                    <span class="sp-role-chip"><b>Prompts:</b> ${esc(mp.prompt_profile || '—')}</span>
                    ${overrideInfo}
                </div>
                <div class="sp-card-meta">${mp.run_count || 0} runs | Total cost: ${formatUsd(mp.total_cost_usd || 0)}</div>
            </div>`;
        });
        c.innerHTML = html;

        // Activate buttons
        c.querySelectorAll('.sp-activate-master').forEach(btn => {
            btn.addEventListener('click', async () => {
                const name = btn.dataset.name;
                const eng = getEngName();
                if (!eng) { showToast('No active engagement', true); return; }
                btn.disabled = true;
                try {
                    const r = await fetch(`/api/engagement/${encodeURIComponent(eng)}/master-profile`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ master_profile: name }),
                    });
                    const d = await r.json();
                    if (d.success) {
                        activeMasterProfile = name;
                        renderMasterProfiles();
                        showToast(`Activated master profile "${name}"`);
                    } else { showToast(d.detail || 'Error', true); }
                } catch (e) { showToast('Failed: ' + e.message, true); }
                finally { btn.disabled = false; }
            });
        });

        // Delete buttons
        c.querySelectorAll('.sp-del-master').forEach(btn => {
            btn.addEventListener('click', async () => {
                const name = btn.dataset.name;
                if (!confirm(`Delete master profile "${name}"?`)) return;
                try {
                    await fetch(`/api/settings/master-profiles/${encodeURIComponent(name)}`, { method: 'DELETE' });
                    await loadAndRenderMaster();
                    showToast(`Deleted "${name}"`);
                } catch (e) { showToast('Delete failed', true); }
            });
        });
    }

    function setupMasterProfileForm() {
        const formEl    = document.getElementById('spNewMasterForm');
        const newBtn    = document.getElementById('spNewMasterProfile');
        const cancelBtn = document.getElementById('spCancelMasterProfile');
        const saveBtn   = document.getElementById('spSaveMasterProfile');

        newBtn.addEventListener('click', () => {
            // Populate dropdowns
            const mcSel = document.getElementById('spNewMasterModelConfig');
            mcSel.innerHTML = '<option value="">— Select model config —</option>';
            modelConfigs.forEach(mc => {
                mcSel.innerHTML += `<option value="${esc(mc.name)}">${esc(mc.name)}</option>`;
            });
            const ppSel = document.getElementById('spNewMasterPromptProfile');
            ppSel.innerHTML = '';
            promptProfiles.forEach(pp => {
                ppSel.innerHTML += `<option value="${esc(pp.name)}">${esc(pp.name)}</option>`;
            });
            formEl.classList.toggle('hidden');
        });
        cancelBtn.addEventListener('click', () => formEl.classList.add('hidden'));

        saveBtn.addEventListener('click', async () => {
            const name = document.getElementById('spNewMasterName').value.trim();
            const modelConfig = document.getElementById('spNewMasterModelConfig').value;
            const promptProfile = document.getElementById('spNewMasterPromptProfile').value;
            const desc = document.getElementById('spNewMasterDesc').value.trim();
            if (!name) { showToast('Name required', true); return; }
            if (!modelConfig) { showToast('Select a model config', true); return; }
            if (!promptProfile) { showToast('Select a prompt profile', true); return; }
            saveBtn.disabled = true;
            try {
                const r = await fetch('/api/settings/master-profiles', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, models_config: modelConfig, prompt_profile: promptProfile, description: desc }),
                });
                const d = await r.json();
                if (d.success) {
                    formEl.classList.add('hidden');
                    document.getElementById('spNewMasterName').value = '';
                    document.getElementById('spNewMasterDesc').value = '';
                    await loadAndRenderMaster();
                    showToast(`Created master profile "${name}"`);
                } else { showToast(d.detail || 'Error', true); }
            } catch (e) { showToast('Failed: ' + e.message, true); }
            finally { saveBtn.disabled = false; }
        });
    }

    /* Save Current As... */
    function setupSaveAs() {
        document.getElementById('spSaveAsBtn').addEventListener('click', async () => {
            const eng = getEngName();
            if (!eng) { showToast('No active engagement', true); return; }
            const type = document.getElementById('spSaveAsType').value;
            const name = document.getElementById('spSaveAsName').value.trim();
            if (!name) { showToast('Name required', true); return; }
            try {
                const r = await fetch(`/api/engagement/${encodeURIComponent(eng)}/save-as-profile`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type, name }),
                });
                const d = await r.json();
                if (d.success) {
                    document.getElementById('spSaveAsName').value = '';
                    showToast(`Saved as ${type}: "${name}"`);
                    // Refresh relevant list
                    if (type === 'model_config') { await loadModelConfigs(); renderModelProfiles(); }
                    if (type === 'master_profile') { await loadAndRenderMaster(); }
                } else { showToast(d.detail || 'Error', true); }
            } catch (e) { showToast('Failed: ' + e.message, true); }
        });
    }

    /* ════════════════════════════════════════════════════
     *  HISTORY TAB
     * ════════════════════════════════════════════════════ */

    async function loadAndRenderHistory() {
        await loadProfileHistory();
        renderHistory();
    }

    function renderHistory() {
        const c = document.getElementById('spHistoryList');
        if (!profileHistory.length) {
            c.innerHTML = '<div class="sp-empty">No profile run history yet. Runs are recorded when using master profiles.</div>';
            return;
        }

        let html = '';
        profileHistory.forEach(ph => {
            const runs = ph.runs || [];
            let runsHtml = '';
            if (runs.length) {
                runsHtml = `<table class="sp-history-table">
                    <thead><tr><th>Engagement</th><th>Target</th><th>Duration</th><th>Cost</th><th>Tokens</th><th>Time</th></tr></thead>
                    <tbody>${runs.slice(0, 10).map(r => `
                        <tr>
                            <td>${esc(r.engagement_name || '—')}</td>
                            <td>${esc(r.target || '—')}</td>
                            <td>${formatDuration(r.duration_seconds)}</td>
                            <td>${formatUsd(r.cost_usd)}</td>
                            <td>${(r.tokens || 0).toLocaleString()}</td>
                            <td>${r.timestamp ? new Date(r.timestamp).toLocaleDateString() : '—'}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>`;
            }

            html += `
            <div class="sp-card">
                <div class="sp-card-header">
                    <span class="sp-card-name">${esc(ph.profile_name)}</span>
                    <span class="sp-card-meta">${ph.run_count} runs</span>
                </div>
                <div class="sp-card-desc">${esc(ph.description || '')}</div>
                <div class="sp-history-stats">
                    <span class="sp-stat">Total: ${formatUsd(ph.total_cost_usd)}</span>
                    <span class="sp-stat">Avg: ${formatUsd(ph.avg_cost_usd)}</span>
                    <span class="sp-stat">Avg duration: ${formatDuration(ph.avg_duration_seconds)}</span>
                    <span class="sp-stat">Tokens: ${(ph.total_tokens || 0).toLocaleString()}</span>
                </div>
                ${runsHtml}
            </div>`;
        });
        c.innerHTML = html;
    }

    /* ════════════════════════════════════════════════════
     *  TOAST
     * ════════════════════════════════════════════════════ */

    function showToast(msg, isError) {
        let t = document.getElementById('spToast');
        if (!t) {
            t = document.createElement('div');
            t.id = 'spToast';
            t.className = 'sp-toast';
            document.body.appendChild(t);
        }
        t.textContent = msg;
        t.className = 'sp-toast' + (isError ? ' sp-toast-error' : '');
        t.classList.add('sp-toast-show');
        clearTimeout(t._timer);
        t._timer = setTimeout(() => t.classList.remove('sp-toast-show'), 2400);
    }

    /* ════════════════════════════════════════════════════
     *  OPEN / CLOSE
     * ════════════════════════════════════════════════════ */

    async function openSettings() {
        await Promise.all([
            loadAvailableModels(),
            loadCurrentConfig(),
            loadModelConfigs(),
            loadActiveMasterProfile(),
        ]);
        renderModelForm();
        renderModelProfiles();
        panel.classList.remove('hidden');
    }

    function closeSettings() {
        panel.classList.add('hidden');
    }

    /* ── Event bindings ── */
    toggleBtn.addEventListener('click', openSettings);
    closeBtn.addEventListener('click', closeSettings);
    resetBtn.addEventListener('click', resetAll);
    form.addEventListener('submit', saveEngagementConfig);
    panel.addEventListener('click', (e) => {
        if (e.target === panel) closeSettings();
    });

    setupModelProfileForm();
    setupPromptProfileForm();
    setupPromptEditor();
    setupMasterProfileForm();
    setupSaveAs();
})();
