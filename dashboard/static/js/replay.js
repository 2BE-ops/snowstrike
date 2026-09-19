/**
 * SnowStrike Replay Engine
 *
 * Replays the engagement timeline, driving the network graph,
 * story panel, and agent terminals step by step.
 */

const HexReplay = (() => {
    let events = [];
    let currentIndex = -1;
    let playing = false;
    let speed = 4;
    let intervalId = null;
    let onEventCallback = null;

    // DOM elements
    let slider = null;
    let timeLabel = null;
    let eventCountLabel = null;
    let playBtn = null;

    function init() {
        slider = document.getElementById('replaySlider');
        timeLabel = document.getElementById('replayTime');
        eventCountLabel = document.getElementById('replayCounter');
        playBtn = document.getElementById('replayToggle');

        // Controls
        document.getElementById('replayToggle')?.addEventListener('click', togglePlay);
        document.getElementById('replayStart')?.addEventListener('click', jumpToStart);
        document.getElementById('replayEnd')?.addEventListener('click', jumpToEnd);
        document.getElementById('replayStepBack')?.addEventListener('click', stepBack);
        document.getElementById('replayStepFwd')?.addEventListener('click', stepForward);

        document.getElementById('replaySpeed')?.addEventListener('change', (e) => {
            speed = parseInt(e.target.value) || 4;
        });

        slider?.addEventListener('input', (e) => {
            const idx = parseInt(e.target.value);
            seekTo(idx);
        });
    }

    async function loadTimeline() {
        try {
            const resp = await fetch('/api/timeline');
            const data = await resp.json();
            events = data.events || [];
            if (slider) {
                slider.max = Math.max(0, events.length - 1);
                slider.value = 0;
            }
            updateLabels();
            return events.length;
        } catch (e) {
            console.error('Failed to load timeline:', e);
            return 0;
        }
    }

    function setEventCallback(cb) {
        onEventCallback = cb;
    }

    function togglePlay() {
        if (playing) {
            pause();
        } else {
            play();
        }
    }

    function play() {
        if (events.length === 0) return;
        playing = true;
        if (playBtn) playBtn.textContent = 'Pause';

        // Base interval: 500ms at 1x speed
        const baseInterval = 500;

        if (intervalId) clearInterval(intervalId);
        intervalId = setInterval(() => {
            if (currentIndex >= events.length - 1) {
                pause();
                return;
            }
            stepForward();
        }, baseInterval / speed);
    }

    function pause() {
        playing = false;
        if (playBtn) playBtn.textContent = 'Play';
        if (intervalId) {
            clearInterval(intervalId);
            intervalId = null;
        }
    }

    function stepForward() {
        if (currentIndex >= events.length - 1) return;
        currentIndex++;
        applyEvent(events[currentIndex]);
        updateSlider();
        updateLabels();
    }

    function stepBack() {
        if (currentIndex <= 0) return;
        // Rebuild state from scratch up to currentIndex - 1
        currentIndex--;
        rebuildState();
        updateSlider();
        updateLabels();
    }

    function jumpToStart() {
        pause();
        currentIndex = -1;
        rebuildState();
        updateSlider();
        updateLabels();
    }

    function jumpToEnd() {
        pause();
        currentIndex = events.length - 1;
        rebuildState();
        updateSlider();
        updateLabels();
    }

    function seekTo(idx) {
        pause();
        currentIndex = Math.min(idx, events.length - 1);
        rebuildState();
        updateSlider();
        updateLabels();
    }

    function rebuildState() {
        // Clear everything and replay from 0 to currentIndex
        if (onEventCallback) {
            onEventCallback({ type: 'reset' });
        }
        for (let i = 0; i <= currentIndex; i++) {
            applyEvent(events[i], true);  // silent = true for batch rebuild
        }
    }

    function applyEvent(event, silent) {
        if (!event) return;
        if (onEventCallback) {
            onEventCallback({
                type: 'event',
                event: event,
                index: currentIndex,
                total: events.length,
                silent: !!silent,
            });
        }
    }

    function updateSlider() {
        if (slider) slider.value = currentIndex;
    }

    function updateLabels() {
        if (eventCountLabel) {
            eventCountLabel.textContent = `${currentIndex + 1} / ${events.length}`;
        }
        // Update timestamp display
        const tsEl = document.getElementById('replayTimestamp');
        if (currentIndex >= 0 && events[currentIndex]) {
            const ts = events[currentIndex].ts;
            if (timeLabel) timeLabel.textContent = formatTime(ts);
            if (tsEl) tsEl.textContent = formatTime(ts);
        } else {
            if (timeLabel) timeLabel.textContent = '--:--:--';
            if (tsEl) tsEl.textContent = '--:--:--';
        }
    }

    function formatTime(ts) {
        if (!ts) return '--:--:--';
        try {
            const d = new Date(ts.includes('T') ? ts : ts + 'Z');
            return d.toLocaleTimeString('en-US', { hour12: false });
        } catch {
            return ts.substring(11, 19) || '--:--:--';
        }
    }

    function reset() {
        pause();
        events = [];
        currentIndex = -1;
        if (slider) { slider.max = 0; slider.value = 0; }
        updateLabels();
    }

    function isPlaying() { return playing; }
    function getEvents() { return events; }
    function getCurrentIndex() { return currentIndex; }

    return {
        init,
        loadTimeline,
        setEventCallback,
        togglePlay,
        play,
        pause,
        stepForward,
        stepBack,
        jumpToStart,
        jumpToEnd,
        reset,
        isPlaying,
        getEvents,
        getCurrentIndex,
    };
})();
