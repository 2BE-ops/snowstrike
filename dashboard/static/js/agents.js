/**
 * SnowStrike Agent Activity Module
 *
 * Mission Control now owns the Terminal tab rendering. This module keeps the
 * shared agent metadata helpers and forwards agent stats/activity into
 * HexTerminals so the rest of the dashboard API stays stable.
 */
const HexAgents = (() => {
    const catalog = window.HexAgentCatalog;
    let activityData = [];

    function canonicalAgentName(agentName) {
        return catalog.canonicalAgentName(agentName);
    }

    function getMeta(agentName) {
        return catalog.getMeta(agentName);
    }

    function init() {
        if (window.HexAvatars) {
            HexAvatars.initStates(catalog.getDisplayOrder());
        }
    }

    function addExecution(execution) {
        activityData.unshift(execution);
        if (activityData.length > 200) activityData.length = 200;
    }

    function updateFeed(executions) {
        activityData = executions || [];
        if (window.HexTerminals && typeof HexTerminals.setActivityFeed === 'function') {
            HexTerminals.setActivityFeed(activityData);
        }
    }

    function updateCards(agents, opts) {
        if (window.HexTerminals && typeof HexTerminals.setAgentStats === 'function') {
            HexTerminals.setAgentStats(agents || [], opts || {});
        }
    }

    return {
        init,
        addExecution,
        updateFeed,
        updateCards,
        getMeta,
        canonicalAgentName,
        AGENT_META: catalog.AGENT_META,
    };
})();
