/* ============================================
   CyberShield SOC — Cyber Defense Module
   (Uses backend proxy for NVD; MITRE from CDN)
   ============================================ */

const CyberDefense = (() => {
    let mitreData = null;

    function switchDefenseTab(tab) {
        document.querySelectorAll('.defense-tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.defense-tab[data-defense="${tab}"]`).classList.add('active');
        document.querySelectorAll('.defense-panel').forEach(p => p.classList.remove('active'));
        document.getElementById('defense' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
    }

    // --- CVE Search via Backend Proxy ---
    async function searchCVE(query) {
        const container = document.getElementById('cveResults');
        container.innerHTML = '<div class="card" style="text-align:center;padding:24px;"><span class="loader"></span><p style="margin-top:12px;color:var(--text-muted);">Searching NIST NVD...</p></div>';

        try {
            let url;
            if (/^CVE-\d{4}-\d+$/i.test(query)) {
                url = `/api/nvd/cve?cveId=${encodeURIComponent(query.toUpperCase())}`;
            } else {
                url = `/api/nvd/cve?keywordSearch=${encodeURIComponent(query)}`;
            }

            const data = await App.apiFetch(url);
            renderCVEResults(data, container);
            App.incrementStat('investigations');
            App.logActivity('scan', `CVE search: <strong>${App.escapeHtml(query)}</strong>`);
        } catch (err) {
            container.innerHTML = `<div class="card"><p style="color:var(--accent-red)">❌ CVE search failed: ${App.escapeHtml(err.message)}</p>
            <p style="color:var(--text-muted);font-size:0.85rem;margin-top:8px;">Note: NIST NVD API has rate limits. Please wait a few seconds and try again.</p></div>`;
        }
    }

    function renderCVEResults(data, container) {
        const vulns = data.vulnerabilities || [];

        if (vulns.length === 0) {
            container.innerHTML = '<div class="card"><div class="empty-state"><span class="empty-icon">🔍</span><p>No CVEs found for this search.</p></div></div>';
            return;
        }

        container.innerHTML = vulns.map(v => {
            const cve = v.cve;
            const id = cve.id;
            const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value || 'No description available.';
            const published = cve.published ? new Date(cve.published).toLocaleDateString() : 'N/A';
            const modified = cve.lastModified ? new Date(cve.lastModified).toLocaleDateString() : 'N/A';

            let cvssScore = 'N/A';
            let cvssColor = 'var(--text-muted)';
            let cvssBg = 'rgba(100,116,139,0.15)';

            const metrics = cve.metrics || {};
            const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
            const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
            const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
            const cvss = cvss31 || cvss30 || cvss2;

            if (cvss) {
                cvssScore = cvss.baseScore;
                if (cvssScore >= 9.0) { cvssColor = 'var(--accent-red)'; cvssBg = 'rgba(244,63,94,0.15)'; }
                else if (cvssScore >= 7.0) { cvssColor = 'var(--accent-orange)'; cvssBg = 'rgba(251,146,60,0.15)'; }
                else if (cvssScore >= 4.0) { cvssColor = 'var(--accent-yellow)'; cvssBg = 'rgba(251,191,36,0.15)'; }
                else { cvssColor = 'var(--accent-green)'; cvssBg = 'rgba(52,211,153,0.15)'; }
            }

            return `<div class="cve-item">
                <div class="cve-header">
                    <a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener" class="cve-id" style="text-decoration:none;">${id} ↗</a>
                    <span class="cve-cvss" style="background:${cvssBg};color:${cvssColor};">CVSS ${cvssScore}</span>
                </div>
                <p class="cve-desc">${App.escapeHtml(desc.substring(0, 300))}${desc.length > 300 ? '...' : ''}</p>
                <div class="cve-meta">
                    <span>Published: ${published}</span>
                    <span>Modified: ${modified}</span>
                </div>
            </div>`;
        }).join('');
    }

    // --- MITRE ATT&CK (from CDN — no key needed) ---
    async function loadMITRE() {
        const matrix = document.getElementById('mitreMatrix');

        try {
            const res = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
            const data = await res.json();
            mitreData = data;
            parseMITRE(data, '');
        } catch (err) {
            matrix.innerHTML = `<div class="card">
                <p style="color:var(--accent-red)">❌ Failed to load MITRE ATT&CK data: ${App.escapeHtml(err.message)}</p>
                <p style="color:var(--text-muted);font-size:0.85rem;margin-top:8px;">This may be due to network issues. Try refreshing.</p>
            </div>`;
        }
    }

    function parseMITRE(data, searchQuery) {
        const matrix = document.getElementById('mitreMatrix');
        const objects = data.objects || [];

        const tactics = objects
            .filter(o => o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated)
            .sort((a, b) => {
                const phaseOrder = ['reconnaissance', 'resource-development', 'initial-access', 'execution',
                    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                    'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
                return phaseOrder.indexOf(a.x_mitre_shortname || '') - phaseOrder.indexOf(b.x_mitre_shortname || '');
            });

        const techniques = objects.filter(o =>
            o.type === 'attack-pattern' &&
            !o.revoked &&
            !o.x_mitre_deprecated &&
            !o.x_mitre_is_subtechnique
        );

        const tacticTechniques = {};
        techniques.forEach(t => {
            const phases = t.kill_chain_phases || [];
            phases.forEach(p => {
                if (!tacticTechniques[p.phase_name]) tacticTechniques[p.phase_name] = [];

                const matchesSearch = !searchQuery ||
                    t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    (t.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
                    (t.external_references?.[0]?.external_id || '').toLowerCase().includes(searchQuery.toLowerCase());

                if (!searchQuery || matchesSearch) {
                    tacticTechniques[p.phase_name].push(t);
                }
            });
        });

        const html = tactics.map(tactic => {
            const phase = tactic.x_mitre_shortname;
            const techs = (tacticTechniques[phase] || []).slice(0, 15);

            if (searchQuery && techs.length === 0) return '';

            return `<div class="mitre-tactic">
                <div class="mitre-tactic-header">${App.escapeHtml(tactic.name)}</div>
                ${techs.map(t => {
                    const tid = t.external_references?.[0]?.external_id || '';
                    return `<div class="mitre-technique" onclick="CyberDefense.showTechnique('${tid}')" title="${App.escapeHtml(t.name)}">
                        <span style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:0.75rem;margin-right:6px;">${tid}</span>
                        ${App.escapeHtml(t.name)}
                    </div>`;
                }).join('')}
                ${techs.length === 0 ? '<div class="mitre-technique" style="color:var(--text-muted);cursor:default;">No matching techniques</div>' : ''}
            </div>`;
        }).filter(Boolean).join('');

        matrix.innerHTML = html ? `<div class="mitre-tactics">${html}</div>` :
            '<div class="card"><div class="empty-state"><span class="empty-icon">🔍</span><p>No techniques match your search.</p></div></div>';
    }

    function showTechnique(tid) {
        if (!mitreData) return;

        const tech = mitreData.objects.find(o =>
            o.type === 'attack-pattern' &&
            o.external_references?.some(r => r.external_id === tid)
        );

        if (!tech) return;

        const name = tech.name;
        const desc = (tech.description || 'No description available.').substring(0, 600);
        const platforms = (tech.x_mitre_platforms || []).join(', ');
        const dataSources = (tech.x_mitre_data_sources || []).join(', ');
        const url = tech.external_references?.[0]?.url || '#';

        const modal = document.getElementById('incidentDetailModal');
        document.getElementById('incDetailTitle').textContent = `${tid} — ${name}`;
        document.getElementById('incDetailBody').innerHTML = `
            <div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Description</div>
                <p style="color:var(--text-secondary);line-height:1.6;font-size:0.88rem;">${App.escapeHtml(desc)}${desc.length >= 600 ? '...' : ''}</p>
            </div>
            ${platforms ? `<div style="margin-bottom:12px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Platforms</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                    ${platforms.split(', ').map(p => `<span class="badge badge-info">${App.escapeHtml(p)}</span>`).join('')}
                </div>
            </div>` : ''}
            ${dataSources ? `<div style="margin-bottom:12px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Data Sources</div>
                <p style="color:var(--text-secondary);font-size:0.85rem;">${App.escapeHtml(dataSources)}</p>
            </div>` : ''}
            <a href="${url}" target="_blank" rel="noopener" class="btn btn-primary" style="text-decoration:none;margin-top:8px;">View on MITRE ATT&CK ↗</a>
        `;
        modal.classList.add('show');
    }

    function init() {
        document.querySelectorAll('.defense-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                switchDefenseTab(tab.dataset.defense);
                if (tab.dataset.defense === 'mitre' && !mitreData) {
                    loadMITRE();
                }
            });
        });

        document.getElementById('cveSearchBtn').addEventListener('click', () => {
            const q = document.getElementById('cveInput').value.trim();
            if (q) searchCVE(q);
            else App.toast('Please enter a search query.', 'warning');
        });
        document.getElementById('cveInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('cveSearchBtn').click();
        });

        document.getElementById('mitreSearchBtn').addEventListener('click', () => {
            if (!mitreData) {
                App.toast('MITRE data is still loading...', 'info');
                return;
            }
            const q = document.getElementById('mitreInput').value.trim();
            parseMITRE(mitreData, q);
        });
        document.getElementById('mitreInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('mitreSearchBtn').click();
        });
    }

    return { init, showTechnique };
})();
