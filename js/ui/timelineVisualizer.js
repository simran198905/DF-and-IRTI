/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Multi-Vector Chronological Swimlane Timeline Visualizer
 */

export class ForensicTimelineVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  render(incidents, correlationResult) {
    if (!this.container) return;
    this.container.innerHTML = '';

    if (!incidents || incidents.length === 0) {
      this.container.innerHTML = `<div class="empty-state">No incident forensic evidence loaded.</div>`;
      return;
    }

    // Flatten all events across incidents
    const allEvents = [];
    incidents.forEach(inc => {
      (inc.evidence || []).forEach(ev => {
        allEvents.push({
          ...ev,
          incidentTitle: inc.title,
          incidentVector: inc.vectorType,
          parentIncId: inc.id
        });
      });
    });

    // Sort chronologically
    allEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    const isCausal = correlationResult?.dimensions?.temporal?.causalSequenceValid;
    const timeDelta = correlationResult?.dimensions?.temporal?.deltaMinutes;

    let html = `
      <div class="timeline-meta-bar">
        <div class="timeline-stat">
          <span class="stat-label">Total Multi-Vector Events:</span>
          <span class="stat-value">${allEvents.length}</span>
        </div>
        <div class="timeline-stat">
          <span class="stat-label">Observed Event Span:</span>
          <span class="stat-value">${timeDelta !== null ? `${timeDelta} minutes` : 'Multi-day span'}</span>
        </div>
        <div class="timeline-stat">
          <span class="stat-label">Causality Assessment:</span>
          <span class="stat-value badge ${isCausal ? 'badge-high' : 'badge-neutral'}">${isCausal ? 'Causal Progression Validated' : 'Uncorrelated Sequence'}</span>
        </div>
      </div>
      <div class="timeline-stream">
    `;

    allEvents.forEach((ev, idx) => {
      const date = new Date(ev.timestamp);
      const formattedTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const formattedDate = date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
      
      const isMobile = ev.sourceType === 'mobile_device' || ev.incidentVector.toLowerCase().includes('mobile');
      const vectorBadgeClass = isMobile ? 'vector-mobile' : 'vector-email';
      const vectorName = isMobile ? 'Mobile Forensics' : 'Corporate Email / BEC';

      const indicatorsList = (ev.indicators || []).map(ind => `
        <span class="ioc-chip ${ind.type.includes('ip') || ind.type.includes('domain') ? 'ioc-infra' : 'ioc-id'}">
          <strong>${ind.label || ind.type}:</strong> ${ind.value}
        </span>
      `).join('');

      const mitreTags = (ev.mitreTechniques || []).map(t => `<span class="mitre-tag">${t}</span>`).join('');

      // Add inter-step causal connector annotation
      let deltaAnnotation = '';
      if (idx > 0) {
        const prevTime = new Date(allEvents[idx - 1].timestamp).getTime();
        const currTime = new Date(ev.timestamp).getTime();
        const diffMin = Math.round((currTime - prevTime) / 60000);
        if (diffMin > 0) {
          deltaAnnotation = `<div class="timeline-delta-bridge">⏱ +${diffMin} min offset</div>`;
        }
      }

      html += `
        ${deltaAnnotation}
        <div class="timeline-card ${vectorBadgeClass} severity-${ev.severity || 'medium'}">
          <div class="timeline-card-header">
            <div class="time-col">
              <span class="timestamp-time">${formattedTime}</span>
              <span class="timestamp-date">${formattedDate}</span>
            </div>
            <div class="card-vector-badge ${vectorBadgeClass}">${vectorName}</div>
            <div class="card-title-group">
              <h4 class="event-title">${ev.title}</h4>
              <span class="event-incident-ref">${ev.incidentTitle}</span>
            </div>
            <span class="severity-badge badge-${ev.severity}">${(ev.severity || 'info').toUpperCase()}</span>
          </div>

          <div class="timeline-card-body">
            <p class="event-description">${ev.description}</p>
            ${indicatorsList ? `<div class="event-iocs">${indicatorsList}</div>` : ''}
            ${mitreTags ? `<div class="event-mitre-row"><span class="mitre-label">MITRE ATT&CK:</span> ${mitreTags}</div>` : ''}
          </div>
        </div>
      `;
    });

    html += `</div>`;
    this.container.innerHTML = html;
  }
}
