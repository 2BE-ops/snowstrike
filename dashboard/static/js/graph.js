/**
 * SnowStrike Network Graph Module — Canvas Redesign
 * Cytoscape.js visualization with agent trails, contextual highlighting,
 * filters, and bidirectional conversation linking.
 */
const HexGraph = (() => {
    let cy = null;
    let tooltip = null;
    let showAgents = true;
    let showTrails = false;

    // Agent colors for light theme
    const AGENT_COLORS = {
        "Recon Agent": "#2E8B57", "WebApp Agent": "#4A7FC4",
        "Attack Agent": "#C44A4A",
        "Cloud Agent": "#7E57C2", "BinaryRE Agent": "#A67C2E",
        "OSINT Agent": "#4A90C4", "Reporting Agent": "#7C7C7C",
    };

    const OS_COLORS = {
        linux: "#2E8B57", windows: "#4A7FC4", macos: "#A67C2E",
        freebsd: "#C44A4A", unknown: "#7C7C7C"
    };

    const SEV_COLORS = {
        critical: "#D94040", high: "#CC6B2E", medium: "#B8860B",
        low: "#3B7DD8", info: "#7C7C7C"
    };

    // Active filters
    const filters = { hosts: true, services: true, vulns: true, agents: true, trails: false };

    function init() {
        tooltip = document.createElement("div");
        tooltip.className = "graph-tooltip";
        tooltip.style.display = "none";
        document.body.appendChild(tooltip);

        cy = cytoscape({
            container: document.getElementById("cy"),
            style: [
                // --- Host nodes (border coloured by highest vuln severity) ---
                {
                    selector: 'node[type="host"]',
                    style: {
                        shape: "round-rectangle",
                        width: 64, height: 38,
                        "background-color": function (n) {
                            const sev = n.data("max_severity");
                            return sev ? sevBgColor(sev) : "#FFFFFF";
                        },
                        "border-width": 2,
                        "border-color": function (n) {
                            const sev = n.data("max_severity");
                            return sev ? (SEV_COLORS[sev] || osColor(n.data("os"))) : osColor(n.data("os"));
                        },
                        label: function (n) { return n.data("hostname") || n.data("ip") || n.data("id"); },
                        "font-family": "'Inter', sans-serif",
                        "font-size": 9,
                        "font-weight": "bold",
                        color: "#1A1A1A",
                        "text-valign": "bottom",
                        "text-margin-y": 7,
                        "text-outline-width": 0,
                        "text-background-color": "#F9F7F4",
                        "text-background-opacity": 0.9,
                        "text-background-padding": 2,
                    },
                },
                // --- Service nodes (border coloured by parent host severity) ---
                {
                    selector: 'node[type="service"]',
                    style: {
                        shape: "ellipse",
                        width: 28, height: 28,
                        "background-color": function (n) {
                            const sev = n.data("max_severity");
                            return sev ? sevBgColor(sev) : "#F9F7F4";
                        },
                        "border-width": 1.5,
                        "border-color": function (n) {
                            const sev = n.data("max_severity");
                            return sev ? (SEV_COLORS[sev] || "#2E8B57") : "#2E8B57";
                        },
                        label: function (n) {
                            const port = n.data("port");
                            const name = n.data("service_name");
                            return port ? port + (name ? "/" + name : "") : name || "";
                        },
                        "font-family": "'Inter', sans-serif",
                        "font-size": 7,
                        color: "#6B6560",
                        "text-valign": "bottom",
                        "text-margin-y": 4,
                    },
                },
                // --- Vulnerability nodes ---
                {
                    selector: 'node[type="vuln"]',
                    style: {
                        shape: "diamond",
                        width: 22, height: 22,
                        "background-color": function (n) { return SEV_COLORS[n.data("severity")] || "#7C7C7C"; },
                        "background-opacity": 0.9,
                        "border-width": 0,
                        label: "",
                    },
                },
                // --- Agent nodes ---
                {
                    selector: 'node[type="agent"]',
                    style: {
                        shape: "hexagon",
                        width: 42, height: 42,
                        "background-color": function (n) { return AGENT_COLORS[n.data("agent_name")] || "#7C7C7C"; },
                        "background-opacity": 0.12,
                        "border-width": 2,
                        "border-color": function (n) { return AGENT_COLORS[n.data("agent_name")] || "#7C7C7C"; },
                        label: function (n) { return n.data("short_name") || ""; },
                        "font-family": "'Inter', sans-serif",
                        "font-size": 9,
                        "font-weight": "bold",
                        color: function (n) { return AGENT_COLORS[n.data("agent_name")] || "#7C7C7C"; },
                        "text-valign": "bottom",
                        "text-margin-y": 7,
                    },
                },
                // --- Attacker node ---
                {
                    selector: 'node[type="attacker"]',
                    style: {
                        shape: "star",
                        width: 38, height: 38,
                        "background-color": "#D94040",
                        "background-opacity": 0.2,
                        "border-width": 2,
                        "border-color": "#D94040",
                        label: "YOU",
                        "font-family": "'Inter', sans-serif",
                        "font-size": 9,
                        "font-weight": "bold",
                        color: "#D94040",
                        "text-valign": "bottom",
                        "text-margin-y": 7,
                    },
                },
                // --- Edges ---
                {
                    selector: 'edge[type="has_service"]',
                    style: {
                        width: 1, "line-color": "#E5E0D8",
                        "curve-style": "bezier", "target-arrow-shape": "none",
                    },
                },
                {
                    selector: 'edge[type="has_vuln"]',
                    style: {
                        width: 1.5,
                        "line-color": function (e) { return SEV_COLORS[e.data("severity")] || "#7C7C7C"; },
                        "line-opacity": 0.5,
                        "curve-style": "bezier", "target-arrow-shape": "none",
                        "line-style": "dashed", "line-dash-pattern": [4, 3],
                    },
                },
                {
                    selector: 'edge[type="exploited"]',
                    style: {
                        width: 2.5, "line-color": "#D94040",
                        "curve-style": "bezier",
                        "target-arrow-shape": "triangle",
                        "target-arrow-color": "#D94040",
                        "arrow-scale": 0.8,
                    },
                },
                {
                    selector: 'edge[type="connected"]',
                    style: {
                        width: 1, "line-color": "#D1CCC4",
                        "curve-style": "bezier", "line-style": "dotted",
                    },
                },
                {
                    selector: 'edge[type="agent_discovered"]',
                    style: {
                        width: 1.5,
                        "line-color": function (e) { return AGENT_COLORS[e.data("agent_name")] || "#A39E97"; },
                        "line-opacity": 0.4,
                        "curve-style": "bezier",
                        "target-arrow-shape": "triangle",
                        "target-arrow-color": function (e) { return AGENT_COLORS[e.data("agent_name")] || "#A39E97"; },
                        "arrow-scale": 0.6,
                        "line-style": "dotted",
                        "line-dash-pattern": [3, 4],
                    },
                },
                // --- Agent trail edges ---
                {
                    selector: 'edge[type="agent_trail"]',
                    style: {
                        width: 2,
                        "line-color": function (e) { return AGENT_COLORS[e.data("agent_name")] || "#A39E97"; },
                        "line-opacity": 0.6,
                        "curve-style": "bezier",
                        "target-arrow-shape": "triangle",
                        "target-arrow-color": function (e) { return AGENT_COLORS[e.data("agent_name")] || "#A39E97"; },
                        "arrow-scale": 0.6,
                        "line-style": "solid",
                    },
                },
                // --- Highlighted state ---
                {
                    selector: ".highlighted",
                    style: {
                        "border-width": 4,
                        "border-color": "#D4764E",
                        "overlay-opacity": 0.1,
                        "overlay-color": "#D4764E",
                        "z-index": 999,
                    },
                },
                // --- Selected state ---
                {
                    selector: ":selected",
                    style: {
                        "border-width": 3,
                        "border-color": "#D4764E",
                        "overlay-opacity": 0.08,
                        "overlay-color": "#D4764E",
                    },
                },
            ],
            layout: { name: "preset" },
            minZoom: 0.3,
            maxZoom: 3,
            wheelSensitivity: 0.3,
        });

        // Interactions
        cy.on("mouseover", "node", onNodeHover);
        cy.on("mouseout", "node", onNodeOut);
        cy.on("tap", "node", onNodeTap);
        cy.on("mousemove", onMouseMove);

        // Controls
        document.getElementById("graphFit")?.addEventListener("click", () => cy.fit(undefined, 40));
        document.getElementById("graphRelayout")?.addEventListener("click", () => runLayout());
        document.getElementById("graphToggleAgents")?.addEventListener("click", toggleAgents);

        // Filter pills
        document.querySelectorAll('.filter-pill').forEach(pill => {
            pill.addEventListener('click', () => {
                const filterType = pill.dataset.filter;
                pill.classList.toggle('active');
                filters[filterType] = pill.classList.contains('active');
                applyFilters();

                if (filterType === 'trails') {
                    showTrails = filters.trails;
                    toggleTrailEdges();
                }
            });
        });
    }

    // ---------------------------------------------------------------
    // Filters
    // ---------------------------------------------------------------

    function applyFilters() {
        if (!cy) return;

        cy.batch(() => {
            cy.nodes('[type="host"]').forEach(n => n.style('display', filters.hosts ? 'element' : 'none'));
            cy.nodes('[type="service"]').forEach(n => n.style('display', filters.services ? 'element' : 'none'));
            cy.nodes('[type="vuln"]').forEach(n => n.style('display', filters.vulns ? 'element' : 'none'));
            cy.nodes('[type="agent"]').forEach(n => n.style('display', filters.agents ? 'element' : 'none'));

            // Hide edges connected to hidden nodes
            cy.edges().forEach(e => {
                const srcVisible = e.source().style('display') !== 'none';
                const tgtVisible = e.target().style('display') !== 'none';
                e.style('display', (srcVisible && tgtVisible) ? 'element' : 'none');
            });
        });
    }

    // ---------------------------------------------------------------
    // Agent Trails
    // ---------------------------------------------------------------

    let trailEdges = [];

    function buildAgentTrails(executions) {
        // Clear old trails
        trailEdges.forEach(id => {
            const el = cy.getElementById(id);
            if (el.length) el.remove();
        });
        trailEdges = [];

        if (!executions || !cy) return;

        // Group executions by agent, ordered by time
        const byAgent = {};
        for (const ex of executions) {
            if (!ex.agent || !ex.success) continue;
            if (!byAgent[ex.agent]) byAgent[ex.agent] = [];
            byAgent[ex.agent].push(ex);
        }

        for (const [agent, execs] of Object.entries(byAgent)) {
            const agentId = "agent_" + agent.replace(/\s+/g, "_");
            if (!cy.getElementById(agentId).length) continue;

            // Find hosts touched, in order
            const touchedHosts = [];
            for (const ex of execs) {
                const cmd = (ex.command || "") + " " + (ex.compacted_summary || "");
                cy.nodes('[type="host"]').forEach(hostNode => {
                    const ip = hostNode.data("ip");
                    if (ip && cmd.includes(ip) && !touchedHosts.includes(hostNode.id())) {
                        touchedHosts.push(hostNode.id());
                    }
                });
            }

            // Draw trail: agent -> host1 -> host2 -> ...
            let prevId = agentId;
            for (const hostId of touchedHosts) {
                const edgeId = `trail_${agent.replace(/\s+/g, "_")}_${prevId}_${hostId}`;
                if (!cy.getElementById(edgeId).length) {
                    cy.add({
                        group: "edges",
                        data: {
                            id: edgeId,
                            source: prevId,
                            target: hostId,
                            type: "agent_trail",
                            agent_name: agent,
                        },
                    });
                    trailEdges.push(edgeId);
                }
                prevId = hostId;
            }
        }

        toggleTrailEdges();
        updateTrailLegend();
    }

    function toggleTrailEdges() {
        if (!cy) return;
        cy.edges('[type="agent_trail"]').forEach(e => {
            e.style('display', showTrails ? 'element' : 'none');
        });
    }

    function updateTrailLegend() {
        const legend = document.getElementById('trailLegend');
        if (!legend) return;

        if (!showTrails) {
            legend.classList.remove('visible');
            return;
        }

        const agents = new Set();
        trailEdges.forEach(id => {
            const e = cy.getElementById(id);
            if (e.length) agents.add(e.data('agent_name'));
        });

        if (agents.size === 0) {
            legend.classList.remove('visible');
            return;
        }

        legend.classList.add('visible');
        legend.innerHTML = Array.from(agents).map(a => {
            const color = AGENT_COLORS[a] || '#7C7C7C';
            const short = a.replace(' Agent', '');
            return `<div class="trail-legend-item">
                <span class="trail-legend-dot" style="background:${color}"></span>
                <span>${esc(short)}</span>
            </div>`;
        }).join('');
    }

    // ---------------------------------------------------------------
    // Contextual Highlighting (bidirectional link with conversation)
    // ---------------------------------------------------------------

    let highlightTimeout = null;

    function highlightNode(nodeId) {
        if (!cy) return;
        // Remove previous highlights
        cy.nodes('.highlighted').removeClass('highlighted');

        const node = cy.getElementById(nodeId);
        if (node.length) {
            node.addClass('highlighted');
            cy.animate({ center: { eles: node }, zoom: cy.zoom() }, { duration: 400 });

            // Auto-remove highlight after 3s
            clearTimeout(highlightTimeout);
            highlightTimeout = setTimeout(() => {
                node.removeClass('highlighted');
            }, 3000);
        }
    }

    /**
     * Scroll conversation to mention of a node.
     * Called when user clicks a node on the graph.
     */
    function scrollConversationToNode(nodeData) {
        // Look for discovery events or handoff cards that reference this node
        const ip = nodeData.ip || nodeData.id;
        if (!ip) return;

        const stream = document.getElementById('conversationInner');
        if (!stream) return;

        // Find last element mentioning this IP
        const allElements = stream.querySelectorAll('.discovery-event, .handoff-tool-name, .handoff-context, .msg-bubble');
        let lastMatch = null;
        allElements.forEach(el => {
            if (el.textContent.includes(ip)) lastMatch = el;
        });

        if (lastMatch) {
            lastMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
            // Brief highlight
            lastMatch.style.outline = '2px solid #D4764E';
            lastMatch.style.outlineOffset = '2px';
            setTimeout(() => {
                lastMatch.style.outline = '';
                lastMatch.style.outlineOffset = '';
            }, 2000);
        }
    }

    // ---------------------------------------------------------------
    // Mouse interactions
    // ---------------------------------------------------------------

    let lastMousePos = { x: 0, y: 0 };

    function onMouseMove(e) {
        lastMousePos = { x: e.originalEvent.clientX, y: e.originalEvent.clientY };
        if (tooltip.style.display !== "none") positionTooltip();
    }

    function positionTooltip() {
        const x = lastMousePos.x + 14;
        const y = lastMousePos.y + 14;
        tooltip.style.left = Math.min(x, window.innerWidth - 300) + "px";
        tooltip.style.top = Math.min(y, window.innerHeight - 150) + "px";
    }

    function onNodeHover(evt) {
        const n = evt.target;
        const type = n.data("type");
        let html = "";

        if (type === "host") {
            html = `<div class="tt-label">${esc(n.data("hostname") || n.data("ip"))}</div>`;
            if (n.data("hostname") && n.data("ip")) html += row("IP", n.data("ip"));
            if (n.data("os")) html += row("OS", n.data("os"));
            const svcs = n.data("services");
            if (svcs && svcs.length) {
                html += row("Services", svcs.map(s => s.port + "/" + (s.name || "")).join(", "));
            }
        } else if (type === "service") {
            html = `<div class="tt-label">Port ${esc(String(n.data("port")))}</div>`;
            if (n.data("service_name")) html += row("Service", n.data("service_name"));
            if (n.data("version")) html += row("Version", n.data("version"));
        } else if (type === "vuln") {
            html = `<div class="tt-label">${esc(n.data("title") || "Vulnerability")}</div>`;
            html += row("Severity", n.data("severity") || "unknown");
            if (n.data("cve")) html += row("CVE", n.data("cve"));
        } else if (type === "agent") {
            html = `<div class="tt-label">${esc(n.data("agent_name"))}</div>`;
            if (n.data("tool_runs") != null) html += row("Tool Runs", n.data("tool_runs"));
            if (n.data("successes") != null) html += row("Successes", n.data("successes"));
        } else if (type === "attacker") {
            html = `<div class="tt-label">Attacker (You)</div>`;
        }

        if (html) {
            tooltip.innerHTML = html;
            tooltip.style.display = "block";
            positionTooltip();
        }
    }

    function onNodeOut() { tooltip.style.display = "none"; }

    function onNodeTap(evt) {
        const n = evt.target;
        showNodeDetail(n.data());
        scrollConversationToNode(n.data());
    }

    // ---------------------------------------------------------------
    // Node Detail Panel
    // ---------------------------------------------------------------

    function showNodeDetail(data) {
        const panel = document.getElementById("nodeDetail");
        const title = document.getElementById("nodeDetailTitle");
        const body = document.getElementById("nodeDetailBody");
        if (!panel || !body) return;

        let html = "";
        if (data.type === "host") {
            title.textContent = data.hostname || data.ip || "Host";
            html += detailSection("Host Information", [
                ["IP Address", data.ip],
                ["Hostname", data.hostname || "\u2014"],
                ["OS", data.os || "Unknown"],
            ]);
            if (data.services && data.services.length) {
                let svcRows = data.services.map(s =>
                    `<div class="detail-row"><span class="detail-key">${s.port}/${s.proto || "tcp"}</span><span class="detail-val">${esc(s.name || "")} ${esc(s.version || "")}</span></div>`
                ).join("");
                html += `<div class="detail-section"><div class="detail-section-title">Services (${data.services.length})</div>${svcRows}</div>`;
            }
            if (data.vulns && data.vulns.length) {
                let vulnRows = data.vulns.map(v =>
                    `<div class="detail-row"><span class="badge badge-${v.severity}">${v.severity}</span><span class="detail-val">${esc(v.title)}</span></div>`
                ).join("");
                html += `<div class="detail-section"><div class="detail-section-title">Vulnerabilities (${data.vulns.length})</div>${vulnRows}</div>`;
            }
        } else if (data.type === "service") {
            title.textContent = `Port ${data.port}`;
            html += detailSection("Service", [
                ["Port", data.port], ["Protocol", data.proto || "tcp"],
                ["Service", data.service_name || "\u2014"],
                ["Version", data.version || "\u2014"],
                ["Banner", data.banner || "\u2014"],
            ]);
        } else if (data.type === "vuln") {
            title.textContent = data.title || "Vulnerability";
            html += detailSection("Vulnerability", [
                ["Title", data.title], ["Severity", data.severity],
                ["CVE", data.cve || "\u2014"], ["CVSS", data.cvss || "\u2014"],
                ["Agent", data.agent || "\u2014"],
            ]);
            if (data.description) {
                html += `<div class="detail-section"><div class="detail-section-title">Description</div><div style="font-size:12px;color:var(--text-secondary);line-height:1.6">${esc(data.description)}</div></div>`;
            }
        } else if (data.type === "agent") {
            title.textContent = data.agent_name;
            html += detailSection("Agent", [
                ["Type", data.short_name],
                ["Tool Runs", data.tool_runs || 0],
                ["Successes", data.successes || 0],
                ["Duration", data.total_duration ? data.total_duration.toFixed(1) + "s" : "\u2014"],
            ]);
        }

        body.innerHTML = html;
        panel.classList.remove("hidden");
        requestAnimationFrame(() => panel.classList.add("visible"));
    }

    function hideNodeDetail() {
        const panel = document.getElementById("nodeDetail");
        if (panel) {
            panel.classList.remove("visible");
            setTimeout(() => panel.classList.add("hidden"), 250);
        }
    }

    function detailSection(title, rows) {
        let html = `<div class="detail-section"><div class="detail-section-title">${esc(title)}</div>`;
        for (const [k, v] of rows) {
            if (v == null) continue;
            html += `<div class="detail-row"><span class="detail-key">${esc(k)}</span><span class="detail-val">${esc(String(v))}</span></div>`;
        }
        return html + "</div>";
    }

    // ---------------------------------------------------------------
    // Graph data
    // ---------------------------------------------------------------

    function updateFromNetworkMap(networkMap, agentStats) {
        if (!cy || !networkMap) return;
        cy.elements().remove();

        const nodes = networkMap.nodes || {};
        const edges = networkMap.edges || [];

        for (const [ip, host] of Object.entries(nodes)) {
            const hostMaxSev = highestSeverity(host.vulns);
            cy.add({
                group: "nodes",
                data: {
                    id: "host_" + ip, type: "host", ip: ip,
                    hostname: host.hostname || null, os: host.os || null,
                    services: host.services || [], vulns: host.vulns || [],
                    max_severity: hostMaxSev,
                },
            });

            if (host.services) {
                for (const svc of host.services) {
                    const svcId = `svc_${ip}_${svc.port}`;
                    // Service inherits the host's highest severity
                    cy.add({ group: "nodes", data: { id: svcId, type: "service", port: svc.port, service_name: svc.name || "", version: svc.version || "", proto: svc.protocol || "tcp", max_severity: hostMaxSev } });
                    cy.add({ group: "edges", data: { id: `e_${ip}_${svc.port}`, source: "host_" + ip, target: svcId, type: "has_service" } });
                }
            }

            if (host.vulns) {
                for (let i = 0; i < host.vulns.length; i++) {
                    const v = host.vulns[i];
                    const vulnId = `vuln_${ip}_${i}`;
                    cy.add({ group: "nodes", data: { id: vulnId, type: "vuln", title: v.title || "", severity: v.severity || "info", cve: v.cve || "", description: v.description || "" } });
                    cy.add({ group: "edges", data: { id: `ev_${ip}_${i}`, source: "host_" + ip, target: vulnId, type: "has_vuln", severity: v.severity || "info" } });
                }
            }
        }

        for (const edge of edges) {
            const srcId = "host_" + edge.source;
            const tgtId = "host_" + edge.target;
            if (cy.getElementById(srcId).length && cy.getElementById(tgtId).length) {
                const edgeType = edge.relationship === "exploited" ? "exploited" : "connected";
                cy.add({ group: "edges", data: { id: `ne_${edge.source}_${edge.target}_${edge.relationship}`, source: srcId, target: tgtId, type: edgeType, label: edge.label || "" } });
            }
        }

        if (showAgents && agentStats && agentStats.length) {
            for (const a of agentStats) {
                const meta = (window.HexAgents && HexAgents.getMeta) ? HexAgents.getMeta(a.agent) : { short: a.agent, color: "#7C7C7C" };
                const agentId = "agent_" + a.agent.replace(/\s+/g, "_");
                cy.add({
                    group: "nodes",
                    data: {
                        id: agentId, type: "agent", agent_name: a.agent,
                        short_name: meta.short, tool_runs: a.tool_runs,
                        successes: a.successes, total_duration: a.total_duration,
                    },
                });
            }
        }

        applyFilters();
        runLayout();
    }

    function addAgentDiscoveryEdges(executions) {
        if (!cy || !showAgents || !executions) return;
        const seen = new Set();
        for (const ex of executions) {
            if (!ex.agent || !ex.success) continue;
            const agentId = "agent_" + ex.agent.replace(/\s+/g, "_");
            if (!cy.getElementById(agentId).length) continue;

            cy.nodes('[type="host"]').forEach(hostNode => {
                const ip = hostNode.data("ip");
                const cmd = (ex.command || "") + " " + (ex.compacted_summary || "");
                if (ip && cmd.includes(ip)) {
                    const key = agentId + "_" + hostNode.id();
                    if (!seen.has(key)) {
                        seen.add(key);
                        cy.add({
                            group: "edges",
                            data: {
                                id: "ad_" + key, source: agentId, target: hostNode.id(),
                                type: "agent_discovered", agent_name: ex.agent,
                            },
                        });
                    }
                }
            });
        }

        // Build trails if executions available
        buildAgentTrails(executions);
    }

    function toggleAgents() {
        showAgents = !showAgents;
        filters.agents = showAgents;
        const btn = document.getElementById("graphToggleAgents");
        if (btn) btn.classList.toggle("active", showAgents);
        applyFilters();
    }

    function runLayout() {
        if (!cy || cy.nodes().length === 0) return;
        cy.layout({
            name: "cose",
            animate: true,
            animationDuration: 600,
            fit: true,
            padding: 40,
            nodeRepulsion: function (node) {
                return node.data("type") === "agent" ? 12000 : 6000;
            },
            idealEdgeLength: function (edge) {
                const t = edge.data("type");
                if (t === "has_service") return 50;
                if (t === "has_vuln") return 60;
                if (t === "agent_discovered" || t === "agent_trail") return 120;
                return 90;
            },
            edgeElasticity: 100,
            gravity: 0.25,
            numIter: 300,
            randomize: false,
        }).run();
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    function highestSeverity(vulns) {
        if (!vulns || !vulns.length) return null;
        let best = null;
        let bestRank = -1;
        for (const v of vulns) {
            const s = (v.severity || "info").toLowerCase();
            const rank = SEV_RANK[s] ?? 0;
            if (rank > bestRank) { bestRank = rank; best = s; }
        }
        return best;
    }

    function sevBgColor(sev) {
        // Subtle tinted background for severity — keeps text readable
        const map = {
            critical: "rgba(217,64,64,0.08)",
            high: "rgba(204,107,46,0.08)",
            medium: "rgba(184,134,11,0.06)",
            low: "rgba(59,125,216,0.05)",
            info: "#FFFFFF",
        };
        return map[sev] || "#FFFFFF";
    }

    function osColor(os) {
        if (!os) return OS_COLORS.unknown;
        const l = os.toLowerCase();
        for (const [key, color] of Object.entries(OS_COLORS)) {
            if (l.includes(key)) return color;
        }
        return OS_COLORS.unknown;
    }

    function row(k, v) {
        return `<div class="tt-row"><span class="tt-key">${esc(k)}</span><span class="tt-val">${esc(String(v))}</span></div>`;
    }

    function esc(s) {
        if (!s) return "";
        return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    return {
        init, updateFromNetworkMap, addAgentDiscoveryEdges,
        buildAgentTrails, runLayout, hideNodeDetail, showNodeDetail,
        toggleAgents, highlightNode, scrollConversationToNode,
        getCy: () => cy,
    };
})();
