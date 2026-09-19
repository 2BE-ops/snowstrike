/**
 * SnowStrike AI v7 — Agent Builder (Cytoscape.js Graph Editor)
 *
 * Canvas-based agent graph editor with:
 * - Cytoscape.js graph rendering (agents as nodes, handoffs as edges)
 * - Config sidebar for editing agent properties
 * - Tool marketplace panel with search/filter
 * - Topology presets
 * - Template library
 * - Live validation
 * - Version history & rollback
 */

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════

const API = '/api/builder';
let cy = null;                    // Cytoscape instance
let allTools = [];                // Full tool catalog
let binaryStatus = {};            // tool_name -> bool
let selectedAgent = null;         // Currently selected agent name
let selectedTemplate = null;      // Selected template in modal

// Agent colors matching main.css design tokens
const AGENT_COLORS = {
    recon:      '#2E8B57',
    webapp:     '#4A7FC4',
    browser:    '#6B8E9B',
    attack:     '#C44A4A',
    cloud:      '#7E57C2',
    binary:     '#A67C2E',
    forensics:  '#5C8A8A',
    osint:      '#4A90C4',
    reporting:  '#7C7C7C',
    orchestrator: '#D4764E',
};

function agentColor(name) {
    return AGENT_COLORS[name] || '#888';
}

// ═══════════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════════

async function api(path, opts = {}) {
    const res = await fetch(API + path, {
        headers: { 'Content-Type': 'application/json', ...opts.headers },
        ...opts,
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || res.statusText);
    }
    return res.json();
}

// ═══════════════════════════════════════════════════════════════
// Toast notifications
// ═══════════════════════════════════════════════════════════════

function toast(msg, type = 'success') {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = `builder-toast ${type} visible`;
    setTimeout(() => el.classList.remove('visible'), 3000);
}

// ═══════════════════════════════════════════════════════════════
// Cytoscape graph initialization
// ═══════════════════════════════════════════════════════════════

function initGraph() {
    cy = cytoscape({
        container: document.getElementById('builderCanvas'),
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'background-color': 'data(color)',
                    'color': '#fff',
                    'font-size': '11px',
                    'font-weight': '600',
                    'font-family': "'Inter', sans-serif",
                    'width': 80,
                    'height': 80,
                    'text-wrap': 'wrap',
                    'text-max-width': '70px',
                    'border-width': 2,
                    'border-color': 'data(color)',
                    'border-opacity': 0.3,
                },
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': '#D4764E',
                    'border-opacity': 1,
                },
            },
            {
                selector: 'node.highlight-error',
                style: {
                    'border-width': 3,
                    'border-color': '#D94040',
                    'border-opacity': 1,
                },
            },
            {
                selector: 'node.highlight-warning',
                style: {
                    'border-width': 3,
                    'border-color': '#B8860B',
                    'border-opacity': 1,
                },
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'arrow-scale': 0.8,
                },
            },
            {
                selector: 'edge[type="dispatch"]',
                style: {
                    'line-color': '#D4764E',
                    'target-arrow-color': '#D4764E',
                    'line-style': 'solid',
                },
            },
            {
                selector: 'edge[type="handoff"]',
                style: {
                    'line-color': '#aaa',
                    'target-arrow-color': '#aaa',
                    'line-style': 'solid',
                },
            },
            {
                selector: 'edge[type="direct_handoff"]',
                style: {
                    'line-color': '#3B7DD8',
                    'target-arrow-color': '#3B7DD8',
                    'line-style': 'dashed',
                },
            },
        ],
        layout: { name: 'preset' },
        minZoom: 0.3,
        maxZoom: 3,
        wheelSensitivity: 0.3,
    });

    // Click node → open config sidebar
    cy.on('tap', 'node', (evt) => {
        const name = evt.target.id();
        if (name === 'orchestrator') return; // Can't edit orchestrator
        openSidebar(name);
    });

    // Click background → close sidebar
    cy.on('tap', (evt) => {
        if (evt.target === cy) closeSidebar();
    });

    // Double-click background → new agent modal
    cy.on('dbltap', (evt) => {
        if (evt.target === cy) showNewAgentModal();
    });
}

// ═══════════════════════════════════════════════════════════════
// Load and render agents on the graph
// ═══════════════════════════════════════════════════════════════

async function loadGraph() {
    const [agentData, topoData] = await Promise.all([
        api('/agents'),
        loadTopologies(),
    ]);

    const agents = agentData.agents || [];
    cy.elements().remove();

    // Add orchestrator node at center
    cy.add({
        data: {
            id: 'orchestrator',
            label: 'Orchestrator',
            color: agentColor('orchestrator'),
        },
        position: { x: 400, y: 300 },
    });

    // Arrange agents in a circle around orchestrator
    const cx = 400, cyPos = 300, radius = 220;
    agents.forEach((agent, i) => {
        const angle = (2 * Math.PI * i) / agents.length - Math.PI / 2;
        const x = cx + radius * Math.cos(angle);
        const y = cyPos + radius * Math.sin(angle);

        cy.add({
            data: {
                id: agent.name,
                label: `${agent.display_name}\n(${agent.tool_count} tools)`,
                color: agentColor(agent.name),
                toolCount: agent.tool_count,
            },
            position: { x, y },
        });

        // Dispatch edge from orchestrator
        cy.add({
            data: {
                id: `orch-${agent.name}`,
                source: 'orchestrator',
                target: agent.name,
                type: 'dispatch',
            },
        });

        // Handoff edge back to orchestrator
        cy.add({
            data: {
                id: `${agent.name}-orch`,
                source: agent.name,
                target: 'orchestrator',
                type: 'handoff',
            },
        });
    });

    // Load handoff edges from agent configs
    for (const agent of agents) {
        try {
            const config = await api(`/agents/${agent.name}`);
            const targets = config?.spec?.handoff_targets || [];
            for (const target of targets) {
                if (target === 'orchestrator') continue; // Already added
                if (agents.some(a => a.name === target)) {
                    const edgeId = `${agent.name}-${target}`;
                    if (!cy.getElementById(edgeId).length) {
                        cy.add({
                            data: {
                                id: edgeId,
                                source: agent.name,
                                target: target,
                                type: 'direct_handoff',
                            },
                        });
                    }
                }
            }
        } catch (e) {
            // Skip if config load fails
        }
    }

    cy.fit(undefined, 40);
}

// ═══════════════════════════════════════════════════════════════
// Topology management
// ═══════════════════════════════════════════════════════════════

async function loadTopologies() {
    const data = await api('/topologies');
    const select = document.getElementById('topologySelect');
    select.innerHTML = '<option value="">Current</option>';
    for (const topo of data.topologies || []) {
        const opt = document.createElement('option');
        opt.value = topo.name;
        opt.textContent = `${topo.name} (${topo.agent_count} agents)`;
        select.appendChild(opt);
    }
    return data;
}

document.getElementById('topologySelect').addEventListener('change', async (e) => {
    const name = e.target.value;
    if (!name) {
        await loadGraph();
        return;
    }
    try {
        const topo = await api(`/topologies/${name}`);
        renderTopology(topo);
    } catch (err) {
        toast(err.message, 'error');
    }
});

function renderTopology(topo) {
    const spec = topo.spec || {};
    cy.elements().remove();

    // Add orchestrator
    cy.add({
        data: { id: 'orchestrator', label: 'Orchestrator', color: agentColor('orchestrator') },
        position: { x: 400, y: 300 },
    });

    // Add agents
    const agents = spec.agents || [];
    const cx = 400, cyPos = 300, radius = 220;
    agents.forEach((name, i) => {
        const angle = (2 * Math.PI * i) / agents.length - Math.PI / 2;
        cy.add({
            data: { id: name, label: name, color: agentColor(name) },
            position: { x: cx + radius * Math.cos(angle), y: cyPos + radius * Math.sin(angle) },
        });
    });

    // Add edges
    for (const edge of spec.edges || []) {
        const froms = Array.isArray(edge.from) ? edge.from : [edge.from];
        const tos = Array.isArray(edge.to) ? edge.to : [edge.to];
        for (const f of froms) {
            for (const t of tos) {
                if (f === t) continue;
                const edgeId = `${f}-${t}-${edge.type}`;
                if (!cy.getElementById(edgeId).length) {
                    cy.add({
                        data: { id: edgeId, source: f, target: t, type: edge.type },
                    });
                }
            }
        }
    }

    cy.fit(undefined, 40);
}

// ═══════════════════════════════════════════════════════════════
// Tool Marketplace
// ═══════════════════════════════════════════════════════════════

async function loadTools() {
    const [toolData, checkData] = await Promise.all([
        api('/tools'),
        api('/tools/check'),
    ]);
    allTools = toolData.tools || [];
    binaryStatus = checkData.results || {};
    renderTools();
}

function renderTools() {
    const search = (document.getElementById('toolSearch').value || '').toLowerCase();
    const category = document.getElementById('categoryFilter').value;
    const rootFilter = document.getElementById('rootFilter').value;

    let filtered = allTools;
    if (search) {
        filtered = filtered.filter(t =>
            t.name.toLowerCase().includes(search) ||
            t.description.toLowerCase().includes(search)
        );
    }
    if (category) filtered = filtered.filter(t => t.category === category);
    if (rootFilter === 'true') filtered = filtered.filter(t => t.requires_root);
    if (rootFilter === 'false') filtered = filtered.filter(t => !t.requires_root);

    const container = document.getElementById('toolsList');
    container.innerHTML = '';
    for (const tool of filtered) {
        const avail = binaryStatus[tool.name] !== false;
        const card = document.createElement('div');
        card.className = 'tool-card';
        card.draggable = true;
        card.dataset.toolName = tool.name;
        card.innerHTML = `
            <div class="tool-card-name">
                <span class="binary-dot ${avail ? 'available' : 'missing'}"></span>
                ${tool.name}
                ${tool.requires_root ? '<span class="root-badge">ROOT</span>' : ''}
            </div>
            <div class="tool-card-category">${tool.category}</div>
            <div class="tool-card-desc">${tool.description || ''}</div>
        `;
        card.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', tool.name);
            card.classList.add('dragging');
        });
        card.addEventListener('dragend', () => card.classList.remove('dragging'));
        card.addEventListener('click', () => {
            if (selectedAgent) addToolToAgent(tool.name);
        });
        container.appendChild(card);
    }
}

document.getElementById('toolSearch').addEventListener('input', renderTools);
document.getElementById('categoryFilter').addEventListener('change', renderTools);
document.getElementById('rootFilter').addEventListener('change', renderTools);

// ═══════════════════════════════════════════════════════════════
// Config Sidebar
// ═══════════════════════════════════════════════════════════════

async function openSidebar(agentName) {
    selectedAgent = agentName;
    const sidebar = document.getElementById('configSidebar');
    sidebar.classList.add('visible');

    try {
        const config = await api(`/agents/${agentName}`);
        populateSidebar(config);
    } catch (err) {
        toast(`Failed to load ${agentName}: ${err.message}`, 'error');
    }

    // Highlight node
    cy.nodes().removeClass('selected');
    cy.getElementById(agentName).select();
}

function closeSidebar() {
    selectedAgent = null;
    document.getElementById('configSidebar').classList.remove('visible');
    cy.nodes().unselect();
}

function populateSidebar(config) {
    const spec = config.spec || {};
    const meta = config.metadata || {};

    document.getElementById('sidebarAgentName').textContent = spec.display_name || meta.name;

    // General tab
    document.getElementById('cfgDisplayName').value = spec.display_name || '';
    document.getElementById('cfgDescription').value = spec.description || '';
    document.getElementById('cfgModel').value = spec.model || 'claude-sonnet-4-20250514';
    document.getElementById('cfgMaxTurns').value = spec.max_turns || 30;
    document.getElementById('cfgMaxTurnsVal').textContent = spec.max_turns || 30;
    document.getElementById('cfgMaxConcurrent').value = spec.max_concurrent || 1;
    document.getElementById('cfgAgentClass').value = spec.agent_class || '';

    // Prompt tab
    const template = spec.prompt?.template || '';
    document.getElementById('cfgPromptTemplate').value = template;

    // Handoff targets
    renderTagList('cfgHandoffTargets', spec.handoff_targets || [], 'cap-tag');

    // Tools tab
    renderToolTags(spec.tools || []);

    // Capabilities tab
    const caps = spec.capabilities || {};
    renderTagList('cfgSkills', caps.skills || [], 'cap-tag');
    renderTagList('cfgProduces', caps.produces || [], 'cap-tag');
    renderTagList('cfgRequires', caps.requires || [], 'cap-tag requires');

    // Switch to general tab
    switchTab('general');
}

function renderToolTags(tools) {
    const container = document.getElementById('cfgTools');
    container.innerHTML = '';
    document.getElementById('toolCount').textContent = tools.length;
    for (const name of tools) {
        const tag = document.createElement('span');
        tag.className = 'tool-tag';
        const avail = binaryStatus[name] !== false;
        tag.innerHTML = `
            <span class="binary-dot ${avail ? 'available' : 'missing'}"></span>
            ${name}
            <span class="remove-tool" data-tool="${name}">&times;</span>
        `;
        tag.querySelector('.remove-tool').addEventListener('click', () => removeToolFromAgent(name));
        container.appendChild(tag);
    }
}

function renderTagList(containerId, items, className) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';
    for (const item of items) {
        const tag = document.createElement('span');
        tag.className = className;
        tag.textContent = item;
        container.appendChild(tag);
    }
}

function addToolToAgent(toolName) {
    const container = document.getElementById('cfgTools');
    const existing = container.querySelectorAll('.tool-tag');
    for (const el of existing) {
        if (el.textContent.trim().replace('×', '').trim() === toolName) return;
    }
    const tools = getToolList();
    tools.push(toolName);
    renderToolTags(tools);
}

function removeToolFromAgent(toolName) {
    const tools = getToolList().filter(t => t !== toolName);
    renderToolTags(tools);
}

function getToolList() {
    const tags = document.querySelectorAll('#cfgTools .tool-tag');
    return Array.from(tags).map(el => {
        const rm = el.querySelector('.remove-tool');
        return rm ? rm.dataset.tool : '';
    }).filter(Boolean);
}

// Tab switching
document.querySelectorAll('.sidebar-tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

function switchTab(tabName) {
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${tabName}`));
}

// Max turns slider
document.getElementById('cfgMaxTurns').addEventListener('input', (e) => {
    document.getElementById('cfgMaxTurnsVal').textContent = e.target.value;
});

// Save agent
document.getElementById('btnSaveAgent').addEventListener('click', async () => {
    if (!selectedAgent) return;
    const body = {
        display_name: document.getElementById('cfgDisplayName').value,
        description: document.getElementById('cfgDescription').value,
        model: document.getElementById('cfgModel').value,
        max_turns: parseInt(document.getElementById('cfgMaxTurns').value),
        max_concurrent: parseInt(document.getElementById('cfgMaxConcurrent').value),
        agent_class: document.getElementById('cfgAgentClass').value || null,
        prompt_template: document.getElementById('cfgPromptTemplate').value || null,
        tools: getToolList(),
    };
    try {
        await api(`/agents/${selectedAgent}`, {
            method: 'PUT',
            body: JSON.stringify(body),
        });
        toast(`Agent "${selectedAgent}" saved`);
        await loadGraph();
        openSidebar(selectedAgent);
    } catch (err) {
        toast(err.message, 'error');
    }
});

// Close sidebar
document.getElementById('closeSidebar').addEventListener('click', closeSidebar);

// ═══════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════

document.getElementById('btnValidate').addEventListener('click', async () => {
    try {
        const result = await api('/validate', { method: 'POST' });
        showValidation(result);
    } catch (err) {
        toast(err.message, 'error');
    }
});

function showValidation(result) {
    const panel = document.getElementById('validationPanel');
    const status = document.getElementById('validationStatus');
    const list = document.getElementById('validationList');

    panel.classList.add('visible');

    if (result.valid) {
        status.innerHTML = '<span class="valid">&#10003; Valid</span> — no errors found';
    } else {
        status.innerHTML = `<span class="invalid">&#10007; Invalid</span> — ${result.errors.length} error(s), ${result.warnings.length} warning(s)`;
    }

    list.innerHTML = '';

    // Clear graph highlights
    cy.nodes().removeClass('highlight-error highlight-warning');

    for (const err of result.errors || []) {
        const item = document.createElement('div');
        item.className = 'validation-item error';
        if (err.type === 'missing_binary') {
            item.textContent = `Missing binary: ${err.binary || err.tool} (agent: ${err.agent})`;
            cy.getElementById(err.agent).addClass('highlight-error');
        } else if (err.type === 'circular_handoff') {
            item.textContent = `Circular handoff: ${err.cycle.join(' → ')}`;
        } else {
            item.textContent = JSON.stringify(err);
        }
        list.appendChild(item);
    }

    for (const warn of result.warnings || []) {
        const item = document.createElement('div');
        item.className = 'validation-item warning';
        if (warn.type === 'missing_api_key') {
            item.textContent = `Missing API key: ${warn.env_var} for ${warn.model} (agent: ${warn.agent})`;
            cy.getElementById(warn.agent).addClass('highlight-warning');
        } else if (warn.type === 'missing_prompt') {
            item.textContent = `Missing prompt template: ${warn.template} (agent: ${warn.agent})`;
        } else if (warn.type === 'unreachable_agent') {
            item.textContent = `Unreachable agent: ${warn.agent}`;
            cy.getElementById(warn.agent).addClass('highlight-warning');
        } else {
            item.textContent = JSON.stringify(warn);
        }
        list.appendChild(item);
    }
}

document.getElementById('closeValidation').addEventListener('click', () => {
    document.getElementById('validationPanel').classList.remove('visible');
    cy.nodes().removeClass('highlight-error highlight-warning');
});

// ═══════════════════════════════════════════════════════════════
// Hot Reload
// ═══════════════════════════════════════════════════════════════

document.getElementById('btnReload').addEventListener('click', async () => {
    try {
        const result = await api('/reload', { method: 'POST' });
        toast(`Reloaded: ${result.agents} agents, ${result.tools} tools`);
        await loadGraph();
    } catch (err) {
        toast(err.message, 'error');
    }
});

// ═══════════════════════════════════════════════════════════════
// New Agent Modal
// ═══════════════════════════════════════════════════════════════

function showNewAgentModal() {
    document.getElementById('newAgentModal').classList.add('visible');
    document.getElementById('newAgentName').value = '';
    document.getElementById('newAgentDisplayName').value = '';
    document.getElementById('newAgentDescription').value = '';
    document.getElementById('newAgentName').focus();
}

document.getElementById('btnNewAgent').addEventListener('click', showNewAgentModal);
document.getElementById('closeNewAgentModal').addEventListener('click', () => {
    document.getElementById('newAgentModal').classList.remove('visible');
});
document.getElementById('btnCancelNewAgent').addEventListener('click', () => {
    document.getElementById('newAgentModal').classList.remove('visible');
});

document.getElementById('btnCreateAgent').addEventListener('click', async () => {
    const name = document.getElementById('newAgentName').value.trim();
    const displayName = document.getElementById('newAgentDisplayName').value.trim();
    const description = document.getElementById('newAgentDescription').value.trim();

    if (!name) { toast('Agent name is required', 'error'); return; }

    try {
        await api('/agents', {
            method: 'POST',
            body: JSON.stringify({
                name,
                display_name: displayName || name,
                description,
            }),
        });
        document.getElementById('newAgentModal').classList.remove('visible');
        toast(`Agent "${name}" created`);
        await loadGraph();
        openSidebar(name);
    } catch (err) {
        toast(err.message, 'error');
    }
});

// ═══════════════════════════════════════════════════════════════
// Template Modal
// ═══════════════════════════════════════════════════════════════

document.getElementById('btnTemplates').addEventListener('click', async () => {
    selectedTemplate = null;
    document.getElementById('templateModal').classList.add('visible');
    document.getElementById('cloneName').value = '';
    document.getElementById('btnCloneTemplate').disabled = true;

    try {
        const data = await api('/templates');
        renderTemplates(data.templates || []);
    } catch (err) {
        toast(err.message, 'error');
    }
});

function renderTemplates(templates) {
    const grid = document.getElementById('templateGrid');
    grid.innerHTML = '';
    for (const tmpl of templates) {
        const card = document.createElement('div');
        card.className = 'template-card';
        card.innerHTML = `
            <div class="template-card-name">${tmpl.display_name || tmpl.name}</div>
            <div class="template-card-desc">${tmpl.description || ''}</div>
            <div class="template-card-tools">${tmpl.tool_count} tools</div>
        `;
        card.addEventListener('click', () => {
            document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            selectedTemplate = tmpl.name;
            document.getElementById('btnCloneTemplate').disabled = false;
        });
        grid.appendChild(card);
    }
}

document.getElementById('closeTemplateModal').addEventListener('click', () => {
    document.getElementById('templateModal').classList.remove('visible');
});
document.getElementById('btnCancelTemplate').addEventListener('click', () => {
    document.getElementById('templateModal').classList.remove('visible');
});

document.getElementById('btnCloneTemplate').addEventListener('click', async () => {
    if (!selectedTemplate) return;
    const newName = document.getElementById('cloneName').value.trim();
    if (!newName) { toast('Enter a name for the new agent', 'error'); return; }

    try {
        await api(`/templates/${selectedTemplate}/clone?new_name=${encodeURIComponent(newName)}`, {
            method: 'POST',
        });
        document.getElementById('templateModal').classList.remove('visible');
        toast(`Cloned "${selectedTemplate}" as "${newName}"`);
        await loadGraph();
        openSidebar(newName);
    } catch (err) {
        toast(err.message, 'error');
    }
});

// ═══════════════════════════════════════════════════════════════
// Version History Modal
// ═══════════════════════════════════════════════════════════════

document.getElementById('btnVersionHistory').addEventListener('click', async () => {
    if (!selectedAgent) return;
    document.getElementById('versionModal').classList.add('visible');

    try {
        const data = await api(`/agents/${selectedAgent}/versions`);
        renderVersions(data.versions || []);
    } catch (err) {
        toast(err.message, 'error');
    }
});

function renderVersions(versions) {
    const body = document.getElementById('versionTableBody');
    body.innerHTML = '';
    if (versions.length === 0) {
        body.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted)">No version history yet</td></tr>';
        return;
    }
    for (const v of versions) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>v${v.version}</td>
            <td>${v.created || '—'}</td>
            <td>${v.author || '—'}</td>
            <td><button class="btn-rollback" data-version="${v.version}">Rollback</button></td>
        `;
        tr.querySelector('.btn-rollback').addEventListener('click', async () => {
            if (!confirm(`Rollback ${selectedAgent} to v${v.version}?`)) return;
            try {
                await api(`/agents/${selectedAgent}/rollback/${v.version}`, { method: 'POST' });
                toast(`Rolled back to v${v.version}`);
                document.getElementById('versionModal').classList.remove('visible');
                await loadGraph();
                openSidebar(selectedAgent);
            } catch (err) {
                toast(err.message, 'error');
            }
        });
        body.appendChild(tr);
    }
}

document.getElementById('closeVersionModal').addEventListener('click', () => {
    document.getElementById('versionModal').classList.remove('visible');
});

// ═══════════════════════════════════════════════════════════════
// Marketplace toggle
// ═══════════════════════════════════════════════════════════════

document.getElementById('toggleMarketplace').addEventListener('click', toggleMarketplace);
document.getElementById('toggleMarketplaceBtn').addEventListener('click', toggleMarketplace);

function toggleMarketplace() {
    document.getElementById('marketplace').classList.toggle('collapsed');
}

// ═══════════════════════════════════════════════════════════════
// Drop zone on canvas (drag tool from marketplace onto canvas)
// ═══════════════════════════════════════════════════════════════

const canvas = document.getElementById('builderCanvas');
canvas.addEventListener('dragover', (e) => e.preventDefault());
canvas.addEventListener('drop', (e) => {
    e.preventDefault();
    const toolName = e.dataTransfer.getData('text/plain');
    if (toolName && selectedAgent) {
        addToolToAgent(toolName);
    }
});

// ═══════════════════════════════════════════════════════════════
// Builder page route (add to dashboard app)
// ═══════════════════════════════════════════════════════════════

document.getElementById('topologySelect').addEventListener('change', async (e) => {
    // Handled above
});

// ═══════════════════════════════════════════════════════════════
// Initialize
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    initGraph();
    await Promise.all([loadGraph(), loadTools()]);
});
