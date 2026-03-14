/* ============================================
   CyberShield SOC — Threat Intel Feed Module
   (Uses backend proxy for AlienVault OTX)
   ============================================ */

const ThreatFeed = (() => {
    let bookmarks = JSON.parse(localStorage.getItem('soc_bookmarked_pulses') || '[]');

    // --- Fetch Pulses via Backend Proxy ---
    async function fetchPulses(searchQuery) {
        const container = document.getElementById('feedResults');
        container.innerHTML = '<div class="card" style="text-align:center;padding:24px;"><span class="loader"></span><p style="margin-top:12px;color:var(--text-muted);">Loading threat intelligence...</p></div>';

        try {
            let url;
            if (searchQuery) {
                url = `/api/otx/search?q=${encodeURIComponent(searchQuery)}`;
            } else {
                url = `/api/otx/pulses/subscribed`;
            }

            const data = await App.apiFetch(url);
            const pulses = data.results || [];
            renderPulses(pulses, container);
        } catch (err) {
            container.innerHTML = `<div class="card">
                <p style="color:var(--accent-red)">❌ Failed to load pulses: ${App.escapeHtml(err.message)}</p>
                <p style="color:var(--text-muted);font-size:0.85rem;margin-top:8px;">Make sure the OTX API key is configured in the server .env file.</p>
            </div>`;
        }
    }

    function renderPulses(pulses, container) {
        if (pulses.length === 0) {
            container.innerHTML = '<div class="card"><div class="empty-state"><span class="empty-icon">📡</span><p>No pulses found.</p></div></div>';
            return;
        }

        container.innerHTML = pulses.map(pulse => {
            const tags = (pulse.tags || []).slice(0, 5);
            const date = pulse.created ? new Date(pulse.created).toLocaleDateString() : 'N/A';
            const isBookmarked = bookmarks.includes(pulse.id);

            return `<div class="pulse-card" data-pulse-id="${pulse.id}">
                <div class="pulse-header">
                    <div style="flex:1;">
                        <div class="pulse-title">${App.escapeHtml(pulse.name || 'Untitled Pulse')}</div>
                        <span class="pulse-date">${date} · ${pulse.indicator_count || 0} IOCs</span>
                    </div>
                    <button class="btn btn-sm ${isBookmarked ? 'btn-primary' : 'btn-ghost'}" onclick="event.stopPropagation(); ThreatFeed.toggleBookmark('${pulse.id}')" title="${isBookmarked ? 'Unbookmark' : 'Bookmark'}">
                        ${isBookmarked ? '⭐' : '☆'}
                    </button>
                </div>
                <p class="pulse-desc">${App.escapeHtml(pulse.description || 'No description provided.')}</p>
                <div class="pulse-tags">
                    ${tags.map(t => `<span class="pulse-tag">${App.escapeHtml(t)}</span>`).join('')}
                    ${pulse.targeted_countries?.length ? `<span class="pulse-tag" style="background:rgba(244,63,94,0.12);color:var(--accent-red);">🎯 ${pulse.targeted_countries.join(', ')}</span>` : ''}
                    ${pulse.adversary ? `<span class="pulse-tag" style="background:rgba(251,146,60,0.12);color:var(--accent-orange);">👤 ${App.escapeHtml(pulse.adversary)}</span>` : ''}
                </div>
            </div>`;
        }).join('');

        container.querySelectorAll('.pulse-card').forEach(card => {
            card.addEventListener('click', () => {
                const pulseId = card.dataset.pulseId;
                const pulse = pulses.find(p => p.id === pulseId);
                if (pulse) showPulseDetail(pulse);
            });
        });
    }

    function showPulseDetail(pulse) {
        const modal = document.getElementById('pulseDetailModal');
        document.getElementById('pulseDetailTitle').textContent = pulse.name || 'Pulse Detail';

        const indicators = (pulse.indicators || []).slice(0, 30);
        const tags = pulse.tags || [];

        document.getElementById('pulseDetailBody').innerHTML = `
            <div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Author</div>
                <div class="abuse-detail-value">${App.escapeHtml(pulse.author_name || 'Unknown')}</div>
            </div>
            <div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Description</div>
                <p style="color:var(--text-secondary);line-height:1.6;font-size:0.88rem;">${App.escapeHtml(pulse.description || 'No description.')}</p>
            </div>
            ${pulse.adversary ? `<div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Adversary</div>
                <div class="abuse-detail-value" style="color:var(--accent-orange);">👤 ${App.escapeHtml(pulse.adversary)}</div>
            </div>` : ''}
            ${tags.length > 0 ? `<div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Tags</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                    ${tags.map(t => `<span class="pulse-tag">${App.escapeHtml(t)}</span>`).join('')}
                </div>
            </div>` : ''}
            <div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:8px;">Indicators of Compromise (${pulse.indicator_count || indicators.length})</div>
                ${indicators.length > 0 ? `
                    <div style="max-height:300px;overflow-y:auto;">
                        ${indicators.map(ind => {
                            const typeColor = ind.type?.includes('IPv4') ? 'var(--accent-cyan)' :
                                              ind.type?.includes('domain') ? 'var(--accent-green)' :
                                              ind.type?.includes('URL') ? 'var(--accent-orange)' :
                                              ind.type?.includes('FileHash') ? 'var(--accent-purple)' :
                                              'var(--text-secondary)';
                            return `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-bottom:1px solid rgba(255,255,255,0.03);font-size:0.83rem;">
                                <span style="font-family:var(--font-mono);color:var(--accent-cyan);word-break:break-all;">${App.escapeHtml(ind.indicator || '')}</span>
                                <span class="badge" style="background:${typeColor}20;color:${typeColor};white-space:nowrap;margin-left:8px;">${App.escapeHtml(ind.type || 'unknown')}</span>
                            </div>`;
                        }).join('')}
                    </div>
                ` : '<p style="color:var(--text-muted);font-size:0.85rem;">No indicators available in preview.</p>'}
            </div>
            <div style="display:flex;gap:8px;">
                <a href="https://otx.alienvault.com/pulse/${pulse.id}" target="_blank" rel="noopener" class="btn btn-primary" style="text-decoration:none;">View on OTX ↗</a>
            </div>
        `;

        modal.classList.add('show');
    }

    function toggleBookmark(pulseId) {
        const idx = bookmarks.indexOf(pulseId);
        if (idx >= 0) {
            bookmarks.splice(idx, 1);
            App.toast('Pulse unbookmarked.', 'info');
        } else {
            bookmarks.push(pulseId);
            App.toast('Pulse bookmarked! ⭐', 'success');
        }
        localStorage.setItem('soc_bookmarked_pulses', JSON.stringify(bookmarks));

        document.querySelectorAll('.pulse-card').forEach(card => {
            const id = card.dataset.pulseId;
            const btn = card.querySelector('.btn');
            if (id && btn) {
                const isBookmarked = bookmarks.includes(id);
                btn.className = `btn btn-sm ${isBookmarked ? 'btn-primary' : 'btn-ghost'}`;
                btn.textContent = isBookmarked ? '⭐' : '☆';
            }
        });
    }

    function init() {
        document.getElementById('refreshFeed').addEventListener('click', () => fetchPulses(''));

        document.getElementById('feedSearchBtn').addEventListener('click', () => {
            const q = document.getElementById('feedSearchInput').value.trim();
            fetchPulses(q);
        });
        document.getElementById('feedSearchInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('feedSearchBtn').click();
        });

        document.getElementById('closePulseDetail').addEventListener('click', () => {
            document.getElementById('pulseDetailModal').classList.remove('show');
        });
        document.getElementById('pulseDetailModal').addEventListener('click', (e) => {
            if (e.target.id === 'pulseDetailModal') e.target.classList.remove('show');
        });

        // Auto-load when tab opens (server checks if key exists)
        window.addEventListener('tabChanged', (e) => {
            if (e.detail.tab === 'threat-feed') {
                fetchPulses('');
            }
        });
    }

    return { init, toggleBookmark };
})();
