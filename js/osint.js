/* ============================================
   CyberShield SOC — OSINT Tools Module
   (Uses backend proxy — keys never exposed)
   ============================================ */

const OSINTTools = (() => {

    // --- Tab switching ---
    function switchOsintTab(tab) {
        document.querySelectorAll('.osint-tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.osint-tab[data-osint="${tab}"]`).classList.add('active');
        document.querySelectorAll('.osint-panel').forEach(p => p.classList.remove('active'));
        document.getElementById('osint' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
    }

    // --- IP Geolocation via Backend Proxy ---
    async function geoLookup(ip) {
        try {
            const data = await App.apiFetch(`/api/ipinfo/${encodeURIComponent(ip)}`);
            renderGeo(data);
            App.incrementStat('investigations');
            App.incrementStat('iocs_scanned');
            App.logActivity('scan', `Geolocated IP <strong>${App.escapeHtml(ip)}</strong>`);
        } catch (err) {
            App.toast(`Geo lookup failed: ${err.message}`, 'error');
        }
    }

    function renderGeo(data) {
        const grid = document.getElementById('geoGrid');
        document.getElementById('geoResults').classList.remove('hidden');

        const fields = [
            { label: 'IP Address', value: data.ip },
            { label: 'Hostname', value: data.hostname || 'N/A' },
            { label: 'City', value: data.city || 'N/A' },
            { label: 'Region', value: data.region || 'N/A' },
            { label: 'Country', value: data.country || 'N/A' },
            { label: 'Location', value: data.loc || 'N/A' },
            { label: 'Organization', value: data.org || 'N/A' },
            { label: 'Postal', value: data.postal || 'N/A' },
            { label: 'Timezone', value: data.timezone || 'N/A' },
            { label: 'ASN', value: data.asn?.asn || (data.org ? data.org.split(' ')[0] : 'N/A') }
        ];

        grid.innerHTML = fields.map(f => `
            <div class="geo-card">
                <div class="geo-card-label">${f.label}</div>
                <div class="geo-card-value">${App.escapeHtml(f.value)}</div>
            </div>
        `).join('');
    }

    // --- URLhaus via Backend Proxy ---
    async function urlScan(url) {
        try {
            const data = await App.apiFetch('/api/urlhaus', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            renderUrlResult(data, url);
            App.incrementStat('investigations');
            App.incrementStat('iocs_scanned');
            App.logActivity('scan', `Scanned URL via URLhaus`);
        } catch (err) {
            App.toast(`URLhaus scan failed: ${err.message}`, 'error');
        }
    }

    function renderUrlResult(data, originalUrl) {
        const card = document.getElementById('urlResultsCard');
        document.getElementById('urlResults').classList.remove('hidden');

        if (data.query_status === 'no_results') {
            card.innerHTML = `
                <div style="text-align:center;padding:24px;">
                    <span style="font-size:2.5rem;">✅</span>
                    <h3 style="color:var(--accent-green);margin:10px 0;">URL Not Found in URLhaus</h3>
                    <p style="color:var(--text-secondary);font-size:0.9rem;">
                        <strong>${App.escapeHtml(originalUrl)}</strong> is not listed in the URLhaus malware database.
                    </p>
                    <p style="color:var(--text-muted);font-size:0.8rem;margin-top:8px;">
                        Note: This doesn't guarantee the URL is safe. It just means it hasn't been reported yet.
                    </p>
                </div>
            `;
            return;
        }

        const threat = data.threat || 'N/A';
        const status = data.url_status || 'N/A';
        const added = data.date_added || 'N/A';
        const tags = (data.tags || []).join(', ') || 'None';
        const isOnline = status === 'online';
        const statusColor = isOnline ? 'var(--accent-red)' : 'var(--accent-green)';

        card.innerHTML = `
            <div style="text-align:center;padding:24px;">
                <span style="font-size:2.5rem;">${isOnline ? '🔴' : '🟡'}</span>
                <h3 style="color:var(--accent-red);margin:10px 0;">⚠️ URL Found in URLhaus!</h3>
            </div>
            <div class="abuse-summary">
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Threat</div>
                    <div class="abuse-detail-value">${App.escapeHtml(threat)}</div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Status</div>
                    <div class="abuse-detail-value" style="color:${statusColor}">${App.escapeHtml(status)}</div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Date Added</div>
                    <div class="abuse-detail-value">${App.escapeHtml(added)}</div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Tags</div>
                    <div class="abuse-detail-value">${App.escapeHtml(tags)}</div>
                </div>
            </div>
        `;

        App.incrementStat('threats');
        App.logActivity('threat', `URLhaus detected malicious URL`);
    }

    // --- Bulk IOC Scan (uses backend proxy routes) ---
    async function bulkScan() {
        const text = document.getElementById('bulkInput').value.trim();
        if (!text) {
            App.toast('Please paste IOCs to scan.', 'warning');
            return;
        }

        const iocs = text.split('\n').map(l => l.trim()).filter(Boolean);
        const container = document.getElementById('bulkResults');
        container.innerHTML = `<div class="card"><span class="loader"></span> Scanning ${iocs.length} IOC(s)...</div>`;

        const results = [];

        for (const ioc of iocs) {
            const type = App.detectIOCType(ioc);
            let status = 'Unknown';
            let detail = '';

            try {
                if (type === 'ip') {
                    const data = await App.apiFetch(`/api/ipinfo/${encodeURIComponent(ioc)}`);
                    status = 'Resolved';
                    detail = `${data.city || '?'}, ${data.country || '?'} — ${data.org || 'N/A'}`;
                } else if (type === 'url') {
                    const data = await App.apiFetch('/api/urlhaus', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: ioc })
                    });
                    if (data.query_status === 'no_results') {
                        status = 'Clean';
                        detail = 'Not in URLhaus';
                    } else {
                        status = 'Malicious';
                        detail = `Threat: ${data.threat || 'Unknown'}`;
                    }
                } else {
                    status = 'Skipped';
                    detail = `Type: ${type}. Use Threat Hunter for full analysis.`;
                }
            } catch (err) {
                status = 'Error';
                detail = err.message;
            }

            results.push({ ioc, type, status, detail });
            App.incrementStat('iocs_scanned');
        }

        container._bulkResults = results;

        container.innerHTML = results.map(r => {
            const color = r.status === 'Malicious' ? 'var(--accent-red)' :
                          r.status === 'Clean' ? 'var(--accent-green)' :
                          r.status === 'Resolved' ? 'var(--accent-cyan)' :
                          'var(--text-muted)';
            return `<div class="card" style="padding:14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="font-family:var(--font-mono);color:var(--accent-cyan);">${App.escapeHtml(r.ioc)}</span>
                    <span style="font-size:0.78rem;color:var(--text-muted);margin-left:8px;">(${r.type})</span>
                    <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:2px;">${App.escapeHtml(r.detail)}</div>
                </div>
                <span class="badge" style="background:${color}20;color:${color};">${r.status}</span>
            </div>`;
        }).join('');

        App.logActivity('scan', `Bulk scanned <strong>${iocs.length}</strong> IOCs`);
    }

    function exportBulkResults() {
        const container = document.getElementById('bulkResults');
        const results = container._bulkResults;
        if (!results || results.length === 0) {
            App.toast('No results to export.', 'warning');
            return;
        }
        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `bulk_scan_${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        App.toast('Results exported!', 'success');
    }

    function init() {
        document.querySelectorAll('.osint-tab').forEach(tab => {
            tab.addEventListener('click', () => switchOsintTab(tab.dataset.osint));
        });

        document.getElementById('geoLookupBtn').addEventListener('click', () => {
            const ip = document.getElementById('geoIpInput').value.trim();
            if (ip) geoLookup(ip);
            else App.toast('Please enter an IP address.', 'warning');
        });
        document.getElementById('geoIpInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('geoLookupBtn').click();
        });

        document.getElementById('urlScanBtn').addEventListener('click', () => {
            const url = document.getElementById('urlScanInput').value.trim();
            if (url) urlScan(url);
            else App.toast('Please enter a URL.', 'warning');
        });
        document.getElementById('urlScanInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('urlScanBtn').click();
        });

        document.getElementById('bulkScanBtn').addEventListener('click', bulkScan);
        document.getElementById('bulkExportBtn').addEventListener('click', exportBulkResults);
    }

    return { init };
})();
