/* ============================================
   CyberShield SOC — Threat Hunter Module
   (Uses backend proxy — keys never exposed)
   ============================================ */

const ThreatHunter = (() => {
    let currentType = 'ip';

    const placeholders = {
        ip: 'Enter an IP address to investigate...',
        domain: 'Enter a domain name to investigate...',
        hash: 'Enter a file hash (MD5/SHA1/SHA256)...',
        url: 'Enter a URL to scan...'
    };

    function setIOCType(type) {
        currentType = type;
        document.querySelectorAll('.ioc-type').forEach(b => b.classList.remove('active'));
        document.querySelector(`.ioc-type[data-type="${type}"]`).classList.add('active');
        document.getElementById('iocInput').placeholder = placeholders[type];
    }

    // --- VirusTotal via Backend Proxy ---
    async function queryVirusTotal(ioc, type) {
        let url;
        if (type === 'ip') url = `/api/vt/ip/${encodeURIComponent(ioc)}`;
        else if (type === 'domain') url = `/api/vt/domain/${encodeURIComponent(ioc)}`;
        else if (type === 'hash') url = `/api/vt/file/${encodeURIComponent(ioc)}`;
        else if (type === 'url') {
            const urlId = btoa(ioc).replace(/=/g, '');
            url = `/api/vt/url/${encodeURIComponent(urlId)}`;
        }
        return App.apiFetch(url);
    }

    // --- AbuseIPDB via Backend Proxy ---
    async function queryAbuseIPDB(ip) {
        return App.apiFetch(`/api/abuseipdb/${encodeURIComponent(ip)}`);
    }

    // --- Render VT Results ---
    function renderVTResults(data) {
        const attrs = data.data?.attributes || {};
        const stats = attrs.last_analysis_stats || {};
        const results = attrs.last_analysis_results || {};

        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        const total = malicious + suspicious + harmless + undetected;

        document.getElementById('vtSummary').innerHTML = `
            <div class="vt-stat">
                <span class="vt-stat-value" style="color: var(--accent-red)">${malicious}</span>
                <span class="vt-stat-label">Malicious</span>
            </div>
            <div class="vt-stat">
                <span class="vt-stat-value" style="color: var(--accent-orange)">${suspicious}</span>
                <span class="vt-stat-label">Suspicious</span>
            </div>
            <div class="vt-stat">
                <span class="vt-stat-value" style="color: var(--accent-green)">${harmless}</span>
                <span class="vt-stat-label">Harmless</span>
            </div>
            <div class="vt-stat">
                <span class="vt-stat-value" style="color: var(--text-muted)">${undetected}</span>
                <span class="vt-stat-label">Undetected</span>
            </div>
            <div class="vt-stat">
                <span class="vt-stat-value" style="color: var(--accent-cyan)">${total}</span>
                <span class="vt-stat-label">Total Engines</span>
            </div>
        `;

        const detections = Object.entries(results)
            .filter(([_, r]) => r.category === 'malicious' || r.category === 'suspicious')
            .map(([engine, r]) => {
                const color = r.category === 'malicious' ? 'var(--accent-red)' : 'var(--accent-orange)';
                return `<div class="vt-engine">
                    <span class="vt-engine-name">${App.escapeHtml(engine)}</span>
                    <span class="badge" style="background: ${color}20; color: ${color}">${App.escapeHtml(r.result || r.category)}</span>
                </div>`;
            });

        if (detections.length > 0) {
            document.getElementById('vtDetections').innerHTML =
                `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:8px;">Flagged by ${detections.length} engines:</p>` +
                detections.join('');
        } else {
            document.getElementById('vtDetections').innerHTML =
                `<p style="color:var(--accent-green);font-size:0.9rem;">✅ No engines flagged this indicator.</p>`;
        }

        return { malicious, suspicious, total };
    }

    // --- Render AbuseIPDB Results ---
    function renderAbuseResults(data) {
        const d = data.data || {};
        const score = d.abuseConfidenceScore || 0;
        const scoreColor = score >= 75 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-orange)' : score >= 10 ? 'var(--accent-yellow)' : 'var(--accent-green)';

        document.getElementById('abuseSummary').innerHTML = `
            <div class="abuse-detail">
                <div class="abuse-detail-label">Confidence Score</div>
                <div class="abuse-detail-value" style="color:${scoreColor};font-size:1.4rem">${score}%</div>
            </div>
            <div class="abuse-detail">
                <div class="abuse-detail-label">Total Reports</div>
                <div class="abuse-detail-value">${d.totalReports || 0}</div>
            </div>
            <div class="abuse-detail">
                <div class="abuse-detail-label">ISP</div>
                <div class="abuse-detail-value">${App.escapeHtml(d.isp || 'N/A')}</div>
            </div>
            <div class="abuse-detail">
                <div class="abuse-detail-label">Country</div>
                <div class="abuse-detail-value">${d.countryCode || 'N/A'} ${d.countryName ? '— ' + App.escapeHtml(d.countryName) : ''}</div>
            </div>
            <div class="abuse-detail">
                <div class="abuse-detail-label">Usage Type</div>
                <div class="abuse-detail-value">${App.escapeHtml(d.usageType || 'N/A')}</div>
            </div>
            <div class="abuse-detail">
                <div class="abuse-detail-label">Domain</div>
                <div class="abuse-detail-value">${App.escapeHtml(d.domain || 'N/A')}</div>
            </div>
        `;

        return { score, reports: d.totalReports || 0 };
    }

    // --- Verdict ---
    function setVerdict(vtResult, abuseResult) {
        const card = document.getElementById('verdictCard');
        const icon = document.getElementById('verdictIcon');
        const title = document.getElementById('verdictTitle');
        const sub = document.getElementById('verdictSub');
        const score = document.getElementById('verdictScore');

        card.className = 'card verdict-card';

        let riskScore = 0;
        let vtInfo = '';
        let abuseInfo = '';

        if (vtResult) {
            riskScore += (vtResult.malicious / Math.max(vtResult.total, 1)) * 70;
            riskScore += (vtResult.suspicious / Math.max(vtResult.total, 1)) * 30;
            vtInfo = `VT: ${vtResult.malicious}/${vtResult.total} detections`;
        }

        if (abuseResult) {
            riskScore = Math.max(riskScore, abuseResult.score);
            abuseInfo = `Abuse: ${abuseResult.score}% confidence, ${abuseResult.reports} reports`;
        }

        riskScore = Math.round(Math.min(riskScore, 100));

        if (riskScore >= 60) {
            card.classList.add('verdict-malicious');
            icon.textContent = '🔴';
            title.textContent = 'MALICIOUS';
            title.style.color = 'var(--accent-red)';
            score.style.color = 'var(--accent-red)';
            App.incrementStat('threats');
        } else if (riskScore >= 20) {
            card.classList.add('verdict-suspicious');
            icon.textContent = '🟡';
            title.textContent = 'SUSPICIOUS';
            title.style.color = 'var(--accent-yellow)';
            score.style.color = 'var(--accent-yellow)';
        } else {
            card.classList.add('verdict-safe');
            icon.textContent = '🟢';
            title.textContent = 'CLEAN';
            title.style.color = 'var(--accent-green)';
            score.style.color = 'var(--accent-green)';
        }

        score.textContent = `${riskScore}/100`;
        sub.textContent = [vtInfo, abuseInfo].filter(Boolean).join(' | ');
    }

    // --- Search History ---
    function addToHistory(ioc, type, riskScore) {
        const history = JSON.parse(localStorage.getItem('soc_search_history') || '[]');
        history.unshift({
            ioc, type, riskScore,
            timestamp: new Date().toISOString()
        });
        if (history.length > 50) history.length = 50;
        localStorage.setItem('soc_search_history', JSON.stringify(history));
        renderHistory();
    }

    function renderHistory() {
        const container = document.getElementById('searchHistory');
        const history = JSON.parse(localStorage.getItem('soc_search_history') || '[]');

        if (history.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <span class="empty-icon">🔍</span>
                <p>No investigations yet. Start by entering an IOC above.</p>
            </div>`;
            return;
        }

        container.innerHTML = history.map(h => {
            const badgeClass = h.riskScore >= 60 ? 'badge-malicious' : h.riskScore >= 20 ? 'badge-suspicious' : 'badge-safe';
            const badgeLabel = h.riskScore >= 60 ? 'Malicious' : h.riskScore >= 20 ? 'Suspicious' : 'Clean';
            return `<div class="history-item" data-ioc="${App.escapeHtml(h.ioc)}" data-type="${h.type}">
                <span class="history-ioc">${App.escapeHtml(h.ioc)}</span>
                <span class="history-meta">
                    <span class="badge ${badgeClass}">${badgeLabel}</span>
                    <span class="history-time">${App.formatTime(h.timestamp)}</span>
                </span>
            </div>`;
        }).join('');

        container.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => {
                const ioc = item.dataset.ioc;
                const type = item.dataset.type;
                setIOCType(type);
                document.getElementById('iocInput').value = ioc;
                search(ioc, type);
            });
        });
    }

    // --- Main Search ---
    async function search(ioc, type) {
        if (!ioc) {
            App.toast('Please enter an IOC to analyze.', 'warning');
            return;
        }

        const btn = document.getElementById('iocSearchBtn');
        btn.querySelector('.btn-text').classList.add('hidden');
        btn.querySelector('.btn-loader').classList.remove('hidden');
        btn.disabled = true;

        document.getElementById('threatResults').classList.remove('hidden');
        document.getElementById('vtSummary').innerHTML = '<span class="loader"></span>';
        document.getElementById('vtDetections').innerHTML = '';
        document.getElementById('abuseSummary').innerHTML = '';

        let vtResult = null;
        let abuseResult = null;

        // VirusTotal via proxy
        try {
            const vtData = await queryVirusTotal(ioc, type);
            vtResult = renderVTResults(vtData);
        } catch (err) {
            document.getElementById('vtSummary').innerHTML =
                `<p style="color:var(--accent-red)">❌ ${App.escapeHtml(err.message)}</p>`;
        }

        // AbuseIPDB via proxy (only for IPs)
        if (type === 'ip') {
            try {
                const abuseData = await queryAbuseIPDB(ioc);
                abuseResult = renderAbuseResults(abuseData);
            } catch (err) {
                document.getElementById('abuseSummary').innerHTML =
                    `<p style="color:var(--accent-red)">❌ ${App.escapeHtml(err.message)}</p>`;
            }
            document.getElementById('abuseResultsCard').classList.remove('hidden');
        } else {
            document.getElementById('abuseResultsCard').classList.add('hidden');
        }

        setVerdict(vtResult, abuseResult);

        App.incrementStat('investigations');
        App.incrementStat('iocs_scanned');

        const riskScore = vtResult ? Math.round((vtResult.malicious / Math.max(vtResult.total, 1)) * 100) : 0;
        addToHistory(ioc, type, Math.max(riskScore, abuseResult?.score || 0));
        App.logActivity(
            riskScore >= 60 || (abuseResult?.score || 0) >= 60 ? 'threat' : 'scan',
            `Investigated <strong>${App.escapeHtml(ioc)}</strong> (${type})`
        );

        btn.querySelector('.btn-text').classList.remove('hidden');
        btn.querySelector('.btn-loader').classList.add('hidden');
        btn.disabled = false;
    }

    function init() {
        document.querySelectorAll('.ioc-type').forEach(btn => {
            btn.addEventListener('click', () => setIOCType(btn.dataset.type));
        });

        document.getElementById('iocSearchBtn').addEventListener('click', () => {
            const ioc = document.getElementById('iocInput').value.trim();
            const detected = App.detectIOCType(ioc);
            if (detected !== 'unknown') setIOCType(detected);
            search(ioc, currentType);
        });

        document.getElementById('iocInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') document.getElementById('iocSearchBtn').click();
        });

        renderHistory();
    }

    return { init };
})();
