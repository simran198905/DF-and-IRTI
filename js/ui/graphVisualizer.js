/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Interactive Force-Directed Graph Visualizer (HTML5 Canvas Engine)
 */

export class ForensicGraphVisualizer {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.nodes = [];
    this.links = [];
    this.onNodeSelected = options.onNodeSelected || null;
    
    // Physics & Interaction State
    this.width = this.canvas.width = this.canvas.parentElement.clientWidth || 800;
    this.height = this.canvas.height = 540;
    this.scale = 1.0;
    this.panX = this.width / 2;
    this.panY = this.height / 2;
    this.isDragging = false;
    this.draggedNode = null;
    this.hoveredNode = null;
    this.lastMouse = { x: 0, y: 0 };
    this.animating = true;

    this.initListeners();
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  setData(correlationResult, incidents) {
    this.nodes = [];
    this.links = [];
    if (!incidents || incidents.length === 0) return;

    const nodeMap = new Map();

    // Helper to add node
    const addNode = (id, label, type, group, radius, color, metadata = {}) => {
      if (!nodeMap.has(id)) {
        const angle = Math.random() * Math.PI * 2;
        const dist = 50 + Math.random() * 120;
        const node = {
          id,
          label,
          type,
          group,
          radius: radius || 16,
          color: color || '#38bdf8',
          x: Math.cos(angle) * dist,
          y: Math.sin(angle) * dist,
          vx: 0,
          vy: 0,
          metadata
        };
        nodeMap.set(id, node);
        this.nodes.push(node);
      }
      return nodeMap.get(id);
    };

    // 1. Add Incident Nodes
    incidents.forEach((inc, idx) => {
      const isMobile = inc.vectorType.toLowerCase().includes('mobile');
      const incColor = isMobile ? '#10b981' : '#06b6d4';
      const incNode = addNode(inc.id, inc.title.split(':')[0] || inc.id, 'incident', isMobile ? 'mobile' : 'email', 28, incColor, {
        fullName: inc.title,
        vector: inc.vectorType,
        target: inc.targetedUser,
        asset: inc.asset,
        evidenceCount: inc.evidence.length
      });

      // 2. Add Evidence & Indicator Nodes
      inc.evidence.forEach(ev => {
        ev.indicators.forEach(ind => {
          let indColor = '#64748b';
          let radius = 14;

          if (ind.type.includes('ip') || ind.type.includes('domain') || ind.type.includes('url')) {
            indColor = '#ef4444'; // Infrastructure (Red)
            radius = 16;
          } else if (ind.type.includes('account') || ind.type.includes('device') || ind.type.includes('user')) {
            indColor = '#a855f7'; // Identity (Purple)
            radius = 16;
          } else if (ind.type.includes('hash')) {
            indColor = '#3b82f6'; // Artifact (Blue)
          }

          const indId = `ind-${ind.type}-${ind.value}`;
          const indNode = addNode(indId, ind.value, ind.type, 'indicator', radius, indColor, {
            typeLabel: ind.label || ind.type,
            indicatorValue: ind.value,
            parentEvent: ev.title,
            timestamp: ev.timestamp
          });

          // Link from Incident to Indicator
          this.links.push({
            source: incNode,
            target: indNode,
            label: 'extracted_from',
            color: 'rgba(100, 116, 139, 0.4)',
            isCrossCorrelated: false
          });
        });
      });
    });

    // 3. Highlight Cross-Incident Correlated Edges & Shared Hubs
    if (correlationResult && correlationResult.sharedEntities) {
      correlationResult.sharedEntities.forEach(shared => {
        const indId = `ind-${shared.type}-${shared.value}`;
        const existingNode = nodeMap.get(indId);
        if (existingNode) {
          existingNode.isShared = true;
          existingNode.radius = 22;
          existingNode.color = '#e11d48'; // Highlighting Shared Nexus
        }
      });
    }

    // 4. Add Threat Actor Node if enriched
    const tiDim = correlationResult?.dimensions?.threatIntelligence;
    if (tiDim && tiDim.attributedActor) {
      const actorNode = addNode(`actor-${tiDim.attributedActor}`, tiDim.attributedActor, 'threat_actor', 'threat_actor', 32, '#f59e0b', {
        campaigns: tiDim.matches.map(m => m.campaign),
        attributionConfidence: 'High'
      });

      // Link actor to infra
      this.nodes.filter(n => n.type.includes('ip') || n.type.includes('domain')).forEach(infraNode => {
        this.links.push({
          source: actorNode,
          target: infraNode,
          label: 'operates_infra',
          color: '#f59e0b',
          isCrossCorrelated: true
        });
      });
    }

    // Re-center physics
    this.panX = this.width / 2;
    this.panY = this.height / 2;
  }

  initListeners() {
    window.addEventListener('resize', () => {
      this.width = this.canvas.width = this.canvas.parentElement.clientWidth || 800;
      this.height = this.canvas.height = 540;
    });

    this.canvas.addEventListener('mousedown', (e) => {
      const mouse = this.getCanvasMouse(e);
      const clicked = this.findNodeAt(mouse.x, mouse.y);
      if (clicked) {
        this.draggedNode = clicked;
        if (this.onNodeSelected) this.onNodeSelected(clicked);
      } else {
        this.isDragging = true;
      }
      this.lastMouse = { x: e.clientX, y: e.clientY };
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const mouse = this.getCanvasMouse(e);
      this.hoveredNode = this.findNodeAt(mouse.x, mouse.y);
      this.canvas.style.cursor = this.hoveredNode ? 'pointer' : (this.isDragging ? 'grabbing' : 'default');

      if (this.draggedNode) {
        this.draggedNode.x = (mouse.x - this.panX) / this.scale;
        this.draggedNode.y = (mouse.y - this.panY) / this.scale;
        this.draggedNode.vx = 0;
        this.draggedNode.vy = 0;
      } else if (this.isDragging) {
        this.panX += e.clientX - this.lastMouse.x;
        this.panY += e.clientY - this.lastMouse.y;
      }
      this.lastMouse = { x: e.clientX, y: e.clientY };
    });

    window.addEventListener('mouseup', () => {
      this.draggedNode = null;
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.scale = Math.max(0.4, Math.min(2.5, this.scale * zoomFactor));
    });
  }

  getCanvasMouse(e) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  }

  findNodeAt(canvasX, canvasY) {
    const worldX = (canvasX - this.panX) / this.scale;
    const worldY = (canvasY - this.panY) / this.scale;
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dist = Math.hypot(n.x - worldX, n.y - worldY);
      if (dist <= n.radius + 6) return n;
    }
    return null;
  }

  updatePhysics() {
    const repulsion = 450;
    const springLen = 110;
    const springK = 0.05;
    const centerGravity = 0.02;
    const damping = 0.85;

    // Repulsion between nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.hypot(dx, dy) || 1;
        if (dist < 320) {
          const force = (repulsion * repulsion) / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          if (n1 !== this.draggedNode) { n1.vx -= fx * 0.05; n1.vy -= fy * 0.05; }
          if (n2 !== this.draggedNode) { n2.vx += fx * 0.05; n2.vy += fy * 0.05; }
        }
      }

      // Gravity towards center
      if (n1 !== this.draggedNode) {
        n1.vx -= n1.x * centerGravity;
        n1.vy -= n1.y * centerGravity;
      }
    }

    // Spring forces on links
    this.links.forEach(l => {
      const dx = l.target.x - l.source.x;
      const dy = l.target.y - l.source.y;
      const dist = Math.hypot(dx, dy) || 1;
      const displacement = dist - springLen;
      const fx = (dx / dist) * displacement * springK;
      const fy = (dy / dist) * displacement * springK;

      if (l.source !== this.draggedNode) { l.source.vx += fx; l.source.vy += fy; }
      if (l.target !== this.draggedNode) { l.target.vx -= fx; l.target.vy -= fy; }
    });

    // Update positions
    this.nodes.forEach(n => {
      if (n !== this.draggedNode) {
        n.vx *= damping;
        n.vy *= damping;
        n.x += n.vx;
        n.y += n.vy;
      }
    });
  }

  animate() {
    this.updatePhysics();
    this.draw();
    requestAnimationFrame(this.animate);
  }

  draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);

    // Draw Cyber Background Grid
    this.ctx.save();
    this.ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
    this.ctx.lineWidth = 1;
    const gridSize = 40;
    for (let x = 0; x < this.width; x += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, this.height);
      this.ctx.stroke();
    }
    for (let y = 0; y < this.height; y += gridSize) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.width, y);
      this.ctx.stroke();
    }
    this.ctx.restore();

    this.ctx.save();
    this.ctx.translate(this.panX, this.panY);
    this.ctx.scale(this.scale, this.scale);

    // 1. Draw Links
    this.links.forEach(l => {
      this.ctx.beginPath();
      this.ctx.moveTo(l.source.x, l.source.y);
      this.ctx.lineTo(l.target.x, l.target.y);
      this.ctx.strokeStyle = l.color || 'rgba(100, 116, 139, 0.35)';
      this.ctx.lineWidth = l.isCrossCorrelated ? 2.5 : 1.5;
      if (l.isCrossCorrelated) {
        this.ctx.setLineDash([4, 4]);
      } else {
        this.ctx.setLineDash([]);
      }
      this.ctx.stroke();
    });

    // 2. Draw Nodes
    this.nodes.forEach(n => {
      const isHovered = n === this.hoveredNode;
      
      // Node Outer Glow
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, n.radius + (isHovered ? 8 : 4), 0, Math.PI * 2);
      this.ctx.fillStyle = n.color;
      this.ctx.globalAlpha = isHovered ? 0.35 : 0.15;
      this.ctx.fill();
      this.ctx.globalAlpha = 1.0;

      // Node Body
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = '#0f172a';
      this.ctx.fill();
      this.ctx.lineWidth = isHovered ? 3 : 2;
      this.ctx.strokeStyle = n.color;
      this.ctx.stroke();

      // Node Badge or Shared Ring
      if (n.isShared) {
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
        this.ctx.strokeStyle = '#f43f5e';
        this.ctx.lineWidth = 2;
        this.ctx.setLineDash([3, 3]);
        this.ctx.stroke();
        this.ctx.setLineDash([]);
      }

      // Label
      this.ctx.font = '11px "JetBrains Mono", Inter, monospace';
      this.ctx.fillStyle = '#e2e8f0';
      this.ctx.textAlign = 'center';
      const truncated = n.label.length > 20 ? n.label.substring(0, 18) + '…' : n.label;
      this.ctx.fillText(truncated, n.x, n.y + n.radius + 14);
    });

    this.ctx.restore();
  }

  resetZoom() {
    this.scale = 1.0;
    this.panX = this.width / 2;
    this.panY = this.height / 2;
  }
}
