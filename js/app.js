/* ============================================
   CyberShield SOC — Core Application Logic
   (Backend Proxy Mode — keys stay server-side)
   ============================================ */

const App = (() => {
    // --- API Status (fetched from server, no keys stored client-side) ---
    let apiStatus = { VT: false, AbuseIPDB: false, IPInfo: false, OTX: false };

    async function fetchApiStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            apiStatus = data.apis || {};
            updateIndicators();
        } catch (err) {
            console.warn('Could not fetch API status from server:', err.message);
        }
    }

    function hasApi(service) {
        return !!apiStatus[service];
    }

    // --- Activity Log ---
    function logActivity(type, message) {
        const activities = JSON.parse(localStorage.getItem('soc_activities') || '[]');
        activities.unshift({
            type,
            message,
            timestamp: new Date().toISOString()
        });
        if (activities.length > 100) activities.length = 100;
        localStorage.setItem('soc_activities', JSON.stringify(activities));
    }

    function getActivities() {
        return JSON.parse(localStorage.getItem('soc_activities') || '[]');
    }

    // --- Stats ---
    function incrementStat(key) {
        const stats = JSON.parse(localStorage.getItem('soc_stats') || '{}');
        stats[key] = (stats[key] || 0) + 1;
        localStorage.setItem('soc_stats', JSON.stringify(stats));
    }

    function getStat(key) {
        const stats = JSON.parse(localStorage.getItem('soc_stats') || '{}');
        return stats[key] || 0;
    }

    // --- Toast Notifications ---
    function toast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
        const validTypes = ['success', 'error', 'info', 'warning'];
        const safeType = validTypes.includes(type) ? type : 'info';
        const t = document.createElement('div');
        t.className = `toast toast-${safeType}`;
        // Use textContent to prevent XSS — never innerHTML with user content
        const iconSpan = document.createElement('span');
        iconSpan.className = 'toast-icon';
        iconSpan.textContent = icons[safeType] || icons.info;
        const msgSpan = document.createElement('span');
        msgSpan.textContent = message;
        t.appendChild(iconSpan);
        t.appendChild(msgSpan);
        container.appendChild(t);
        setTimeout(() => {
            t.style.animation = 'toastOut 0.3s ease forwards';
            setTimeout(() => t.remove(), 300);
        }, 3500);
    }

    // --- Navigation ---
    const pageTitles = {
        'dashboard': 'Dashboard',
        'threat-hunter': 'Threat Hunter',
        'osint': 'OSINT Tools',
        'incident': 'Incident Response',
        'cyber-defense': 'Cyber Defense',
        'threat-feed': 'Threat Intel Feed'
    };

    function switchTab(tab) {
        document.querySelectorAll('.nav-item[data-tab]').forEach(n => n.classList.remove('active'));
        const activeNav = document.querySelector(`.nav-item[data-tab="${tab}"]`);
        if (activeNav) activeNav.classList.add('active');

        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const panelId = 'panel' + tab.split('-').map((w, i) => w.charAt(0).toUpperCase() + w.slice(1)).join('');
        const panel = document.getElementById(panelId);
        if (panel) panel.classList.add('active');

        document.getElementById('pageTitle').textContent = pageTitles[tab] || tab;
        document.getElementById('sidebar').classList.remove('open');
        window.dispatchEvent(new CustomEvent('tabChanged', { detail: { tab } }));
    }

    // --- Clock ---
    function updateClock() {
        const now = new Date();
        const h = String(now.getHours()).padStart(2, '0');
        const m = String(now.getMinutes()).padStart(2, '0');
        const s = String(now.getSeconds()).padStart(2, '0');
        document.getElementById('headerClock').textContent = `${h}:${m}:${s}`;
    }

    // --- API Indicators ---
    function updateIndicators() {
        document.querySelectorAll('.indicator').forEach(ind => {
            const api = ind.dataset.api;
            ind.classList.toggle('connected', !!apiStatus[api]);
        });
    }

    // --- Utility: Format timestamp ---
    function formatTime(isoStr) {
        const d = new Date(isoStr);
        const now = new Date();
        const diff = Math.floor((now - d) / 1000);
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    // --- Utility: Escape HTML ---
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Utility: Detect IOC type ---
    function detectIOCType(value) {
        value = value.trim();
        // Length limit to prevent ReDoS attacks on regex
        if (value.length > 2048) return 'unknown';
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
        if (/^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) return 'hash';
        if (/^https?:\/\//i.test(value)) return 'url';
        if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(value)) return 'domain';
        return 'unknown';
    }

    // --- Utility: Severity color ---
    function severityClass(sev) {
        const map = { P1: 'badge-p1', P2: 'badge-p2', P3: 'badge-p3', P4: 'badge-p4' };
        return map[sev] || 'badge-info';
    }

    function statusClass(status) {
        const map = {
            'New': 'badge-new',
            'In Progress': 'badge-in-progress',
            'Contained': 'badge-contained',
            'Resolved': 'badge-resolved',
            'Closed': 'badge-closed'
        };
        return map[status] || 'badge-info';
    }

    // --- Fetch wrapper (calls our backend proxy) ---
    async function apiFetch(url, options = {}) {
        try {
            const res = await fetch(url, options);
            if (!res.ok) {
                const text = await res.text();
                let msg;
                try { msg = JSON.parse(text).error; } catch { msg = text.substring(0, 200); }
                throw new Error(msg || `HTTP ${res.status}`);
            }
            return await res.json();
        } catch (err) {
            console.error('API fetch error:', err);
            throw err;
        }
    }

    // --- Settings Modal (now shows server-side key status, no client-side storage) ---
    function initSettings() {
        const modal = document.getElementById('settingsModal');
        const openBtn = document.getElementById('openSettings');
        const closeBtn = document.getElementById('closeSettings');

        openBtn.addEventListener('click', () => {
            // Show server-side key status
            const fields = [
                { id: 'statusVT', api: 'VT', name: 'VirusTotal' },
                { id: 'statusAbuseIPDB', api: 'AbuseIPDB', name: 'AbuseIPDB' },
                { id: 'statusIPInfo', api: 'IPInfo', name: 'ipinfo.io' },
                { id: 'statusOTX', api: 'OTX', name: 'AlienVault OTX' }
            ];
            fields.forEach(f => {
                const el = document.getElementById(f.id);
                if (apiStatus[f.api]) {
                    el.textContent = '✅ Configured on server';
                    el.style.color = '#34d399';
                } else {
                    el.textContent = '❌ Not configured — add to .env file on server';
                    el.style.color = '#f43f5e';
                }
            });
            modal.classList.add('show');
        });

        closeBtn.addEventListener('click', () => modal.classList.remove('show'));
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.remove('show');
        });
    }

    // --- Init ---
    function init() {
        // Navigation
        document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                switchTab(item.dataset.tab);
            });
        });

        // Quick actions
        document.querySelectorAll('.quick-btn[data-action]').forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.action));
        });

        // Hamburger
        document.getElementById('toggleSidebar').addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });

        // Clock
        updateClock();
        setInterval(updateClock, 1000);

        // Fetch API status from server
        fetchApiStatus();

        // Settings
        initSettings();

        // Initialize all modules
        if (typeof Dashboard !== 'undefined') Dashboard.init();
        if (typeof ThreatHunter !== 'undefined') ThreatHunter.init();
        if (typeof OSINTTools !== 'undefined') OSINTTools.init();
        if (typeof IncidentResponse !== 'undefined') IncidentResponse.init();
        if (typeof CyberDefense !== 'undefined') CyberDefense.init();
        if (typeof ThreatFeed !== 'undefined') ThreatFeed.init();

        console.log('%c🛡️ CyberShield SOC Dashboard Loaded (Secure Backend Mode)', 'color: #38bdf8; font-size: 16px; font-weight: bold;');
    }

    document.addEventListener('DOMContentLoaded', init);

    return {
        hasApi,
        logActivity, getActivities,
        incrementStat, getStat,
        toast, switchTab,
        formatTime, escapeHtml, detectIOCType,
        severityClass, statusClass,
        apiFetch, updateIndicators
    };
})();
