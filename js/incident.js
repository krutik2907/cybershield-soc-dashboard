/* ============================================
   CyberShield SOC — Incident Response Module
   (localStorage CRUD)
   ============================================ */

const IncidentResponse = (() => {
    const STORAGE_KEY = 'soc_incidents';

    function getIncidents() {
        return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    }

    function saveIncidents(incidents) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(incidents));
    }

    function generateId() {
        const incidents = getIncidents();
        const num = incidents.length + 1;
        return `INC-${String(num).padStart(4, '0')}`;
    }

    // --- Create Incident ---
    function createIncident() {
        const title = document.getElementById('incTitle').value.trim();
        const severity = document.getElementById('incSeverity').value;
        const type = document.getElementById('incType').value;
        const assets = document.getElementById('incAssets').value.trim();
        const desc = document.getElementById('incDesc').value.trim();
        const iocs = document.getElementById('incIOCs').value.trim();

        if (!title) {
            App.toast('Please enter an incident title.', 'warning');
            return;
        }

        const incident = {
            id: generateId(),
            title,
            severity,
            type,
            assets,
            description: desc,
            iocs: iocs ? iocs.split(',').map(s => s.trim()) : [],
            status: 'New',
            created: new Date().toISOString(),
            updated: new Date().toISOString(),
            timeline: [{
                status: 'New',
                timestamp: new Date().toISOString(),
                note: 'Incident created'
            }]
        };

        const incidents = getIncidents();
        incidents.unshift(incident);
        saveIncidents(incidents);

        // Clear form
        document.getElementById('incTitle').value = '';
        document.getElementById('incDesc').value = '';
        document.getElementById('incAssets').value = '';
        document.getElementById('incIOCs').value = '';
        document.getElementById('incidentForm').classList.add('hidden');

        App.logActivity('incident', `Created incident <strong>${incident.id}</strong>: ${App.escapeHtml(title)}`);
        App.toast(`Incident ${incident.id} created!`, 'success');

        renderTable();
    }

    // --- Update Status ---
    function updateStatus(incidentId, newStatus, note = '') {
        const incidents = getIncidents();
        const inc = incidents.find(i => i.id === incidentId);
        if (!inc) return;

        inc.status = newStatus;
        inc.updated = new Date().toISOString();
        inc.timeline.push({
            status: newStatus,
            timestamp: new Date().toISOString(),
            note: note || `Status changed to ${newStatus}`
        });

        saveIncidents(incidents);
        App.logActivity(
            newStatus === 'Resolved' || newStatus === 'Closed' ? 'resolved' : 'incident',
            `<strong>${incidentId}</strong> → ${newStatus}`
        );
        renderTable();
    }

    // --- Render Table ---
    function renderTable() {
        const tbody = document.getElementById('incidentTableBody');
        const empty = document.getElementById('incidentEmpty');
        let incidents = getIncidents();

        // Filters
        const filterSev = document.getElementById('filterSeverity').value;
        const filterStat = document.getElementById('filterStatus').value;
        if (filterSev) incidents = incidents.filter(i => i.severity === filterSev);
        if (filterStat) incidents = incidents.filter(i => i.status === filterStat);

        if (incidents.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = 'block';
            document.querySelector('#panelIncident .table-wrap').style.display = 'none';
            return;
        }

        empty.style.display = 'none';
        document.querySelector('#panelIncident .table-wrap').style.display = 'block';

        tbody.innerHTML = incidents.map(inc => {
            const sevClass = App.severityClass(inc.severity);
            const statClass = App.statusClass(inc.status);
            const statuses = ['New', 'In Progress', 'Contained', 'Resolved', 'Closed'];
            const nextStatuses = statuses.filter(s => s !== inc.status);

            return `<tr>
                <td>${inc.id}</td>
                <td><span class="badge ${sevClass}">${inc.severity}</span></td>
                <td style="color:var(--text-primary);font-weight:500;">${App.escapeHtml(inc.title)}</td>
                <td>${App.escapeHtml(inc.type)}</td>
                <td><span class="badge-status ${statClass}">${inc.status}</span></td>
                <td style="font-family:var(--font-mono);font-size:0.78rem;">${App.formatTime(inc.created)}</td>
                <td>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">
                        <button class="btn btn-sm btn-ghost" onclick="IncidentResponse.showDetail('${inc.id}')">View</button>
                        <select class="filter-select" style="padding:4px 8px;font-size:0.75rem;min-width:auto;" onchange="IncidentResponse.updateStatus('${inc.id}', this.value); this.value='';">
                            <option value="">Change...</option>
                            ${nextStatuses.map(s => `<option value="${s}">${s}</option>`).join('')}
                        </select>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    // --- Show Detail Modal ---
    function showDetail(incidentId) {
        const incidents = getIncidents();
        const inc = incidents.find(i => i.id === incidentId);
        if (!inc) return;

        const modal = document.getElementById('incidentDetailModal');
        document.getElementById('incDetailTitle').textContent = `${inc.id} — ${inc.title}`;

        const sevClass = App.severityClass(inc.severity);
        const statClass = App.statusClass(inc.status);

        document.getElementById('incDetailBody').innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;">
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Severity</div>
                    <div><span class="badge ${sevClass}">${inc.severity}</span></div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Status</div>
                    <div><span class="badge-status ${statClass}">${inc.status}</span></div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Type</div>
                    <div class="abuse-detail-value">${App.escapeHtml(inc.type)}</div>
                </div>
                <div class="abuse-detail">
                    <div class="abuse-detail-label">Affected Assets</div>
                    <div class="abuse-detail-value">${App.escapeHtml(inc.assets || 'N/A')}</div>
                </div>
            </div>
            <div style="margin-bottom:16px;">
                <div class="abuse-detail-label" style="margin-bottom:6px;">Description</div>
                <p style="color:var(--text-secondary);line-height:1.6;font-size:0.9rem;">${App.escapeHtml(inc.description || 'No description provided.')}</p>
            </div>
            ${inc.iocs.length > 0 ? `
                <div style="margin-bottom:16px;">
                    <div class="abuse-detail-label" style="margin-bottom:6px;">Related IOCs</div>
                    <div style="display:flex;flex-wrap:wrap;gap:6px;">
                        ${inc.iocs.map(i => `<span class="badge badge-info" style="font-family:var(--font-mono);">${App.escapeHtml(i)}</span>`).join('')}
                    </div>
                </div>
            ` : ''}
            <div>
                <div class="abuse-detail-label" style="margin-bottom:10px;">Timeline</div>
                ${inc.timeline.map(t => `
                    <div class="activity-item">
                        <span class="activity-dot ${t.status === 'Resolved' || t.status === 'Closed' ? 'resolved' : 'incident'}"></span>
                        <div>
                            <div class="activity-text"><span class="badge-status ${App.statusClass(t.status)}" style="margin-right:8px;">${t.status}</span> ${App.escapeHtml(t.note)}</div>
                            <div class="activity-time">${App.formatTime(t.timestamp)}</div>
                        </div>
                    </div>
                `).slice().reverse().join('')}
            </div>
        `;

        modal.classList.add('show');
    }

    // --- Export ---
    function exportIncidents() {
        const incidents = getIncidents();
        if (incidents.length === 0) {
            App.toast('No incidents to export.', 'warning');
            return;
        }
        const blob = new Blob([JSON.stringify(incidents, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `incidents_${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        App.toast('Incidents exported!', 'success');
    }

    function init() {
        // New incident button
        document.getElementById('newIncidentBtn').addEventListener('click', () => {
            document.getElementById('incidentForm').classList.toggle('hidden');
        });

        document.getElementById('cancelIncident').addEventListener('click', () => {
            document.getElementById('incidentForm').classList.add('hidden');
        });

        document.getElementById('submitIncident').addEventListener('click', createIncident);

        // Filters
        document.getElementById('filterSeverity').addEventListener('change', renderTable);
        document.getElementById('filterStatus').addEventListener('change', renderTable);

        // Export
        document.getElementById('exportIncidents').addEventListener('click', exportIncidents);

        // Close detail modal
        document.getElementById('closeIncidentDetail').addEventListener('click', () => {
            document.getElementById('incidentDetailModal').classList.remove('show');
        });
        document.getElementById('incidentDetailModal').addEventListener('click', (e) => {
            if (e.target.id === 'incidentDetailModal') e.target.classList.remove('show');
        });

        renderTable();

        // Refresh on tab switch
        window.addEventListener('tabChanged', (e) => {
            if (e.detail.tab === 'incident') renderTable();
        });
    }

    return { init, updateStatus, showDetail };
})();
