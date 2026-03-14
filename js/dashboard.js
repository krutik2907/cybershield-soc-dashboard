/* ============================================
   CyberShield SOC — Dashboard Overview Module
   ============================================ */

const Dashboard = (() => {
    function updateStats() {
        document.getElementById('statInvCount').textContent = App.getStat('investigations');
        document.getElementById('statThreatCount').textContent = App.getStat('threats');
        document.getElementById('statIOCCount').textContent = App.getStat('iocs_scanned');

        // Open incidents
        const incidents = JSON.parse(localStorage.getItem('soc_incidents') || '[]');
        const open = incidents.filter(i => i.status !== 'Closed' && i.status !== 'Resolved').length;
        document.getElementById('statIncCount').textContent = open;
    }

    function updateGauge() {
        const threats = App.getStat('threats');
        const incidents = JSON.parse(localStorage.getItem('soc_incidents') || '[]');
        const openCritical = incidents.filter(i =>
            (i.status !== 'Closed' && i.status !== 'Resolved') && (i.severity === 'P1' || i.severity === 'P2')
        ).length;

        let level = 'LOW';
        let offset = 220; // mostly empty

        if (openCritical >= 3 || threats >= 10) {
            level = 'CRITICAL';
            offset = 20;
        } else if (openCritical >= 2 || threats >= 5) {
            level = 'HIGH';
            offset = 80;
        } else if (openCritical >= 1 || threats >= 2) {
            level = 'MEDIUM';
            offset = 140;
        }

        const arc = document.getElementById('gaugeArc');
        const text = document.getElementById('gaugeText');
        const sub = document.getElementById('gaugeSub');

        if (arc) arc.setAttribute('stroke-dashoffset', offset);
        if (text) text.textContent = level;
        if (sub) sub.textContent = `${threats} active threat${threats !== 1 ? 's' : ''}`;

        const colors = { LOW: '#34d399', MEDIUM: '#fbbf24', HIGH: '#fb923c', CRITICAL: '#f43f5e' };
        if (text) text.setAttribute('fill', colors[level]);
    }

    function renderActivity() {
        const timeline = document.getElementById('activityTimeline');
        const activities = App.getActivities().slice(0, 20);

        if (activities.length === 0) {
            timeline.innerHTML = `<div class="empty-state">
                <span class="empty-icon">📋</span>
                <p>No recent activity. Start investigating!</p>
            </div>`;
            return;
        }

        timeline.innerHTML = activities.map(a => {
            const dotClass = a.type === 'threat' ? 'threat' : a.type === 'incident' ? 'incident' : a.type === 'resolved' ? 'resolved' : '';
            return `<div class="activity-item">
                <span class="activity-dot ${dotClass}"></span>
                <div>
                    <div class="activity-text">${a.message}</div>
                    <div class="activity-time">${App.formatTime(a.timestamp)}</div>
                </div>
            </div>`;
        }).join('');
    }

    function refresh() {
        updateStats();
        updateGauge();
        renderActivity();
    }

    function init() {
        refresh();
        // Refresh when tab is switched to dashboard
        window.addEventListener('tabChanged', (e) => {
            if (e.detail.tab === 'dashboard') refresh();
        });
    }

    return { init, refresh };
})();
