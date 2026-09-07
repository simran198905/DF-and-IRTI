/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Neo4j Graph Visualizer & Cypher Engine
 * Powered by vis.Network (Neo4j Bloom / Browser layout engine) & neo4j-driver
 */

export class ForensicGraphVisualizer {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    this.onNodeSelected = options.onNodeSelected || null;
    this.network = null;
    this.nodesDataSet = null;
    this.edgesDataSet = null;
    this.allNodes = [];
    this.allEdges = [];
    this.currentIncidents = [];
    this.correlationResult = null;
    this.physicsRunning = true;
    this.activeCategoryFilter = null;
    this.searchQuery = '';

    // Neo4j Color Schema (Standard Neo4j Bloom Palettes)
    this.neo4jColors = {
      threatActor: { background: '#FF7C00', border: '#D45B00', highlight: { background: '#FFA540', border: '#FFFFFF' } },
      incidentMobile: { background: '#00C58A', border: '#009966', highlight: { background: '#33D8A3', border: '#FFFFFF' } },
      incidentEmail: { background: '#0099FF', border: '#0077CC', highlight: { background: '#40B5FF', border: '#FFFFFF' } },
      c2Infra: { background: '#E74C3C', border: '#C0392B', highlight: { background: '#FF6B5B', border: '#FFFFFF' } },
      domain: { background: '#FF5722', border: '#E64A19', highlight: { background: '#FF784E', border: '#FFFFFF' } },
      identity: { background: '#9C27B0', border: '#7B1FA2', highlight: { background: '#BA68C8', border: '#FFFFFF' } },
      hash: { background: '#3498DB', border: '#2980B9', highlight: { background: '#5DADE2', border: '#FFFFFF' } },
      device: { background: '#1ABC9C', border: '#16A085', highlight: { background: '#48C9B0', border: '#FFFFFF' } },
      sharedNexus: { background: '#F43F5E', border: '#E11D48', highlight: { background: '#FB7185', border: '#FFFFFF' } }
    };

    this.initNetwork();
  }

  initNetwork() {
    if (!this.container || typeof window.vis === 'undefined') {
      console.warn('vis-network library not loaded or container not found.');
      return;
    }

    this.nodesDataSet = new window.vis.DataSet([]);
    this.edgesDataSet = new window.vis.DataSet([]);

    const data = {
      nodes: this.nodesDataSet,
      edges: this.edgesDataSet
    };

    const options = {
      nodes: {
        shape: 'dot',
        size: 26,
        font: {
          color: '#F8FAFC',
          size: 11,
          face: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          background: 'rgba(11, 16, 30, 0.88)',
          strokeWidth: 0,
          vadjust: 4
        },
        borderWidth: 2.5,
        shadow: {
          enabled: true,
          color: 'rgba(0, 0, 0, 0.65)',
          size: 8,
          x: 2,
          y: 3
        }
      },
      edges: {
        width: 2,
        color: {
          color: 'rgba(100, 116, 139, 0.45)',
          highlight: '#00D563',
          hover: '#38BDF8'
        },
        arrows: {
          to: {
            enabled: true,
            scaleFactor: 0.65
          }
        },
        smooth: {
          enabled: true,
          type: 'curvedCW',
          roundness: 0.14
        },
        font: {
          color: '#94A3B8',
          size: 9,
          face: 'JetBrains Mono, monospace',
          align: 'middle',
          background: 'rgba(13, 20, 36, 0.92)',
          strokeWidth: 0
        },
        selectionWidth: 3.5,
        hoverWidth: 2.5
      },
      physics: {
        enabled: true,
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -85,
          centralGravity: 0.007,
          springLength: 160,
          springConstant: 0.05,
          damping: 0.78,
          avoidOverlap: 0.92 // Prevents node and label overlapping completely
        },
        stabilization: {
          enabled: true,
          iterations: 160,
          updateInterval: 25
        }
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
        selectConnectedEdges: true
      }
    };

    this.network = new window.vis.Network(this.container, data, options);

    // Event listeners
    this.network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const selected = this.allNodes.find(n => n.id === nodeId);
        if (selected && this.onNodeSelected) {
          this.onNodeSelected(selected);
        }
      }
    });

    this.network.on('hoverNode', (params) => {
      this.highlightNeighborhood(params.node);
    });

    this.network.on('blurNode', () => {
      this.clearHighlight();
    });
  }

  setData(correlationResult, incidents) {
    if (!this.network) this.initNetwork();
    if (!incidents || incidents.length === 0) return;

    this.correlationResult = correlationResult;
    this.currentIncidents = incidents;
    this.allNodes = [];
    this.allEdges = [];

    const nodeMap = new Map();
    const sharedSet = new Set();

    if (correlationResult?.sharedEntities) {
      correlationResult.sharedEntities.forEach(s => {
        sharedSet.add(s.value);
        sharedSet.add(`ind-${s.type}-${s.value}`);
      });
    }

    // Helper to add Neo4j node
    const addNeoNode = (id, rawLabel, neo4jLabel, category, colorScheme, size, metadata = {}) => {
      if (!nodeMap.has(id)) {
        let displayLabel = rawLabel;
        if (rawLabel.length > 24) {
          displayLabel = rawLabel.substring(0, 22) + '…';
        }
        if (category === 'hash' && rawLabel.length > 20) {
          displayLabel = `Hash:${rawLabel.substring(0, 6)}…${rawLabel.substring(rawLabel.length - 4)}`;
        }

        const node = {
          id,
          label: `${displayLabel}\n(:${neo4jLabel})`,
          rawLabel,
          neo4jLabel,
          category,
          size: size || 24,
          color: colorScheme,
          font: {
            color: '#FFFFFF',
            size: 11,
            face: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif'
          },
          title: `<div style="font-family:Inter; font-size:12px; padding:4px;">
            <strong style="color:${colorScheme.background}">:${neo4jLabel}</strong><br/>
            <strong>${rawLabel}</strong><br/>
            <span style="color:#94a3b8; font-size:11px;">Category: ${category}</span>
          </div>`,
          metadata
        };
        nodeMap.set(id, node);
        this.allNodes.push(node);
      }
      return nodeMap.get(id);
    };

    // Helper to add Neo4j edge
    const addNeoEdge = (fromId, toId, cypherRel, isNexus = false, isActor = false) => {
      const edge = {
        id: `e-${fromId}-${toId}-${cypherRel}`,
        from: fromId,
        to: toId,
        label: `[:${cypherRel}]`,
        color: isNexus ? { color: '#F43F5E', highlight: '#FB7185' } : (isActor ? { color: '#FF7C00', highlight: '#FFA540' } : { color: 'rgba(148, 163, 184, 0.45)', highlight: '#00D563' }),
        width: isNexus ? 2.8 : (isActor ? 2.2 : 1.8),
        dashes: isNexus ? [5, 5] : (isActor ? [4, 4] : false),
        arrows: { to: { enabled: true, scaleFactor: 0.7 } },
        isNexus,
        cypherRel
      };
      this.allEdges.push(edge);
    };

    // 1. Add Incident Nodes
    const incNodes = [];
    incidents.forEach((inc) => {
      const isMobile = inc.vectorType.toLowerCase().includes('mobile');
      const incLabel = isMobile ? 'Incident_Mobile' : 'Incident_Email';
      const colorScheme = isMobile ? this.neo4jColors.incidentMobile : this.neo4jColors.incidentEmail;

      const incNode = addNeoNode(
        inc.id,
        inc.title.split(':')[0] || inc.id,
        incLabel,
        isMobile ? 'mobile' : 'email',
        colorScheme,
        34,
        {
          fullName: inc.title,
          vector: inc.vectorType,
          target: inc.targetedUser,
          asset: inc.asset,
          evidenceCount: inc.evidence.length
        }
      );
      incNodes.push({ inc, node: incNode });
    });

    // 2. Add Threat Actor Node
    const tiDim = correlationResult?.dimensions?.threatIntelligence;
    let actorNode = null;
    if (tiDim && tiDim.attributedActor) {
      actorNode = addNeoNode(
        `actor-${tiDim.attributedActor}`,
        tiDim.attributedActor,
        'ThreatActor',
        'threat_actor',
        this.neo4jColors.threatActor,
        38,
        {
          actor: tiDim.attributedActor,
          attributionConfidence: 'High (84%)',
          campaigns: tiDim.matches ? tiDim.matches.map(m => m.campaign).join(', ') : 'DoubleFalcon',
          malwareFamily: 'Hermit / Predator Mobile Variant + BEC PhishKit'
        }
      );
    }

    // 3. Add Evidence & Indicator Nodes
    incNodes.forEach(({ inc, node: incNode }) => {
      const evidence = inc.evidence || [];
      evidence.forEach(ev => {
        const indicators = ev.indicators || [];
        indicators.forEach(ind => {
          let neoLabel = 'Artifact';
          let category = 'artifact';
          let colorScheme = this.neo4jColors.hash;
          let size = 20;

          if (ind.type.includes('ip')) {
            neoLabel = 'C2_Infrastructure';
            category = 'ip';
            colorScheme = this.neo4jColors.c2Infra;
            size = 23;
          } else if (ind.type.includes('domain') || ind.type.includes('url')) {
            neoLabel = 'Domain';
            category = 'domain';
            colorScheme = this.neo4jColors.domain;
            size = 23;
          } else if (ind.type.includes('account') || ind.type.includes('user') || ind.type.includes('phone')) {
            neoLabel = 'TargetIdentity';
            category = 'account';
            colorScheme = this.neo4jColors.identity;
            size = 23;
          } else if (ind.type.includes('hash')) {
            neoLabel = 'FileHash';
            category = 'hash';
            colorScheme = this.neo4jColors.hash;
            size = 20;
          } else if (ind.type.includes('app') || ind.type.includes('bundle') || ind.type.includes('device')) {
            neoLabel = 'Device_App';
            category = 'device';
            colorScheme = this.neo4jColors.device;
            size = 20;
          }

          const indId = `ind-${ind.type}-${ind.value}`;
          const isShared = sharedSet.has(ind.value) || sharedSet.has(indId);

          if (isShared) {
            neoLabel = 'SharedNexus';
            category = 'shared';
            colorScheme = this.neo4jColors.sharedNexus;
            size = 26;
          }

          const indNode = addNeoNode(
            indId,
            ind.value,
            neoLabel,
            category,
            colorScheme,
            size,
            {
              indicatorType: ind.type,
              value: ind.value,
              sourceIncident: inc.title,
              parentEvent: ev.title,
              timestamp: ev.timestamp,
              isShared
            }
          );

          // Incident -> Indicator Relationship
          const relName = isShared ? 'CROSS_VECTOR_NEXUS' : 'EXTRACTED_FROM';
          addNeoEdge(incNode.id, indNode.id, relName, isShared, false);
        });
      });
    });

    // 4. Link Threat Actor to C2 Infrastructure & Nexus
    if (actorNode) {
      this.allNodes
        .filter(n => (n.category === 'ip' || n.category === 'domain' || n.category === 'shared') && n.id !== actorNode.id)
        .forEach(infraNode => {
          addNeoEdge(actorNode.id, infraNode.id, 'OPERATES_C2', false, true);
        });
    }

    // Refresh vis network
    this.nodesDataSet.clear();
    this.edgesDataSet.clear();
    this.nodesDataSet.add(this.allNodes);
    this.edgesDataSet.add(this.allEdges);

    this.network.fit({
      animation: { duration: 800, easingFunction: 'easeInOutQuad' }
    });
  }

  highlightNeighborhood(selectedNodeId) {
    if (!this.network) return;
    const connectedNodeIds = this.network.getConnectedNodes(selectedNodeId);
    const connectedEdgeIds = this.network.getConnectedEdges(selectedNodeId);

    const updateNodes = this.allNodes.map(node => {
      const isConnected = node.id === selectedNodeId || connectedNodeIds.includes(node.id);
      return {
        id: node.id,
        opacity: isConnected ? 1.0 : 0.15,
        font: {
          color: isConnected ? '#FFFFFF' : 'rgba(255,255,255,0.2)'
        }
      };
    });

    const updateEdges = this.allEdges.map(edge => {
      const isConnected = connectedEdgeIds.includes(edge.id);
      return {
        id: edge.id,
        opacity: isConnected ? 1.0 : 0.08,
        font: {
          color: isConnected ? '#94A3B8' : 'rgba(148,163,184,0.1)'
        }
      };
    });

    this.nodesDataSet.update(updateNodes);
    this.edgesDataSet.update(updateEdges);
  }

  clearHighlight() {
    if (!this.network) return;
    const resetNodes = this.allNodes.map(node => ({
      id: node.id,
      opacity: 1.0,
      font: { color: '#FFFFFF' }
    }));
    const resetEdges = this.allEdges.map(edge => ({
      id: edge.id,
      opacity: 1.0,
      font: { color: '#94A3B8' }
    }));

    this.nodesDataSet.update(resetNodes);
    this.edgesDataSet.update(resetEdges);
  }

  executeCypherQuery(cypherQuery) {
    if (!cypherQuery || !this.network) return;
    const query = cypherQuery.trim();
    const queryUpper = query.toUpperCase();

    // Reset view if MATCH (n) RETURN n
    if (queryUpper.includes('MATCH (N) RETURN N') || queryUpper === 'MATCH (N) RETURN *') {
      this.clearFilter();
      return { count: this.allNodes.length, message: `Returned all ${this.allNodes.length} graph entities.` };
    }

    let matchedNodeIds = new Set();

    // Check for Label filter e.g. MATCH (n:SharedNexus) or MATCH (i:Incident)
    const labelMatch = query.match(/:([A-Za-z0-9_]+)/);
    const whereMatch = query.match(/WHERE\s+(.+?)(?:RETURN|$)/i);

    if (labelMatch) {
      const targetLabel = labelMatch[1].toLowerCase();
      this.allNodes.forEach(n => {
        if (
          n.neo4jLabel.toLowerCase() === targetLabel ||
          n.category.toLowerCase() === targetLabel ||
          (targetLabel === 'sharednexus' && n.metadata?.isShared)
        ) {
          matchedNodeIds.add(n.id);
        }
      });
    }

    // Check WHERE CONTAINS
    if (whereMatch) {
      const condition = whereMatch[1];
      const containsMatch = condition.match(/CONTAINS\s+['"](.+?)['"]/i);
      if (containsMatch) {
        const needle = containsMatch[1].toLowerCase();
        this.allNodes.forEach(n => {
          if (n.rawLabel.toLowerCase().includes(needle) || JSON.stringify(n.metadata).toLowerCase().includes(needle)) {
            matchedNodeIds.add(n.id);
          }
        });
      }
    }

    if (matchedNodeIds.size === 0) {
      // Fallback: search anywhere in label
      const terms = query.replace(/(MATCH|RETURN|WHERE|\(|\)|\[|\]|:|-|>|<)/gi, ' ').split(/\s+/).filter(t => t.length > 2);
      this.allNodes.forEach(n => {
        terms.forEach(t => {
          if (n.rawLabel.toLowerCase().includes(t.toLowerCase()) || n.neo4jLabel.toLowerCase().includes(t.toLowerCase())) {
            matchedNodeIds.add(n.id);
          }
        });
      });
    }

    if (matchedNodeIds.size > 0) {
      // Dim non-matches
      const updateNodes = this.allNodes.map(node => ({
        id: node.id,
        opacity: matchedNodeIds.has(node.id) ? 1.0 : 0.12
      }));
      this.nodesDataSet.update(updateNodes);
      return { count: matchedNodeIds.size, message: `Query matched ${matchedNodeIds.size} entities.` };
    }

    return { count: 0, message: 'No matching nodes found for Cypher query.' };
  }

  clearFilter() {
    this.clearHighlight();
  }

  setFilter(searchStr) {
    if (!this.network) return;
    const query = (searchStr || '').trim().toLowerCase();
    if (!query) {
      this.clearHighlight();
      return;
    }

    const updateNodes = this.allNodes.map(node => {
      const matches = node.rawLabel.toLowerCase().includes(query) || node.neo4jLabel.toLowerCase().includes(query);
      return {
        id: node.id,
        opacity: matches ? 1.0 : 0.12
      };
    });
    this.nodesDataSet.update(updateNodes);
  }

  setCategoryFilter(category) {
    if (!this.network) return;
    if (this.activeCategoryFilter === category) {
      this.activeCategoryFilter = null;
      this.clearHighlight();
      return;
    }

    this.activeCategoryFilter = category;
    const updateNodes = this.allNodes.map(node => {
      const matches = node.category.toLowerCase().includes(category.toLowerCase()) || node.neo4jLabel.toLowerCase().includes(category.toLowerCase());
      return {
        id: node.id,
        opacity: matches ? 1.0 : 0.12
      };
    });
    this.nodesDataSet.update(updateNodes);
  }

  zoomIn() {
    if (!this.network) return;
    const scale = this.network.getScale() * 1.25;
    this.network.moveTo({ scale, animation: { duration: 250 } });
  }

  zoomOut() {
    if (!this.network) return;
    const scale = this.network.getScale() * 0.8;
    this.network.moveTo({ scale, animation: { duration: 250 } });
  }

  resetZoom() {
    if (!this.network) return;
    this.network.fit({ animation: { duration: 400 } });
  }

  fitToView() {
    this.resetZoom();
  }

  resizeCanvas() {
    if (this.network) {
      this.network.redraw();
      this.network.fit();
    }
  }

  togglePhysics() {
    if (!this.network) return true;
    this.physicsRunning = !this.physicsRunning;
    this.network.setOptions({ physics: { enabled: this.physicsRunning } });
    return this.physicsRunning;
  }

  /**
   * Generates pure Neo4j Cypher (.cql) script representing the entire incident graph
   */
  generateCypherScript() {
    const lines = [
      '// =========================================================================',
      '// Neo4j Cypher Incident Reconstruction Script',
      '// Generated by Cross-Vector Forensic & Threat Intelligence Framework',
      '// =========================================================================\n',
      '// 1. Create Forensic Incident & Entity Nodes'
    ];

    // Nodes
    this.allNodes.forEach(node => {
      const sanitizedId = node.id.replace(/[^a-zA-Z0-9_]/g, '_');
      const cleanLabel = (node.rawLabel || '').replace(/'/g, "\\'");
      const props = [`id: '${sanitizedId}'`, `value: '${cleanLabel}'`];

      if (node.metadata) {
        Object.entries(node.metadata).forEach(([k, v]) => {
          if (typeof v === 'string') {
            props.push(`${k}: '${v.replace(/'/g, "\\'")}'`);
          } else if (typeof v === 'number' || typeof v === 'boolean') {
            props.push(`${k}: ${v}`);
          }
        });
      }

      lines.push(`CREATE (${sanitizedId}:${node.neo4jLabel} { ${props.join(', ')} })`);
    });

    lines.push('\n// 2. Create Directed Forensic Attribution & Causality Relationships');

    // Relationships
    this.allEdges.forEach(edge => {
      const fromId = edge.from.replace(/[^a-zA-Z0-9_]/g, '_');
      const toId = edge.to.replace(/[^a-zA-Z0-9_]/g, '_');
      lines.push(`CREATE (${fromId})-[:${edge.cypherRel}]->(${toId})`);
    });

    lines.push('\nRETURN "Forensic Graph Reconstruction Completed Successfully." AS Status;');
    return lines.join('\n');
  }
}
