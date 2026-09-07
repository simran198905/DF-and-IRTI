/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Engine
 * Implements 6-dimensional forensic cross-correlation
 */

import { IndicatorTypes, EvidenceSourceTypes } from '../models/evidenceSchema.js';

// Generic public CDN/DNS IPs and shared email gateways that should be discounted to avoid false correlations
const PUBLIC_INFRA_FILTER = [
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '127.0.0.1', '0.0.0.0',
  '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', // Cloudflare
  '172.67.', '199.232.', '151.101.', '105.112.' // Public / Residential ISPs / CDNs
];

export function runCrossVectorCorrelation(incidents, threatIntelFeed = []) {
  if (!incidents || incidents.length < 2) {
    return {
      success: false,
      message: 'At least two incidents are required for cross-vector correlation.'
    };
  }

  const incA = incidents[0];
  const incB = incidents[1];

  // 1. Threat Intelligence Enrichment first so other dimensions can leverage campaign intelligence
  const tiResult = correlateThreatIntelligence(incA, incB, threatIntelFeed);

  // 2. Infrastructure Correlation (including direct, subnet, and TI-linked infrastructure)
  const infraResult = correlateInfrastructure(incA, incB, tiResult);

  // 3. Temporal & Causality Correlation
  const temporalResult = correlateTemporalSequence(incA, incB);

  // 4. Identity & Asset Alignment
  const identityResult = correlateIdentity(incA, incB);

  // 5. Artifact & IOC Matching
  const artifactResult = correlateArtifacts(incA, incB);

  // 6. Behavioral & TTP Alignment
  const ttpResult = correlateTTPs(incA, incB);

  // Compute Cross-Incident Shared Indicator List
  const sharedEntities = extractSharedEntities(incA, incB, [
    ...infraResult.matches,
    ...identityResult.matches,
    ...artifactResult.matches,
    ...tiResult.matches
  ]);

  return {
    success: true,
    timestamp: new Date().toISOString(),
    incidentA: { id: incA.id, title: incA.title, type: incA.vectorType },
    incidentB: { id: incB.id, title: incB.title, type: incB.vectorType },
    dimensions: {
      infrastructure: infraResult,
      temporal: temporalResult,
      identity: identityResult,
      artifacts: artifactResult,
      behavioralTTP: ttpResult,
      threatIntelligence: tiResult
    },
    sharedEntities,
    summary: {
      directSharedIOCsCount: sharedEntities.length,
      causalSequenceIdentified: temporalResult.causalSequenceValid,
      sharedTargetIdentified: identityResult.targetMatch,
      threatActorCandidate: tiResult.attributedActor || 'Unclassified / Novel Cluster'
    }
  };
}

/**
 * 1. Infrastructure Correlation
 */
function correlateInfrastructure(incA, incB, tiResult) {
  const matches = [];
  const discounted = [];
  let score = 0;
  let rationale = [];

  const getInfraIndicators = (inc) => {
    const list = [];
    (inc.evidence || []).forEach(ev => {
      ev.indicators.forEach(ind => {
        if ([IndicatorTypes.IP, IndicatorTypes.DOMAIN, IndicatorTypes.URL, IndicatorTypes.CERT_SERIAL].includes(ind.type) ||
            ind.label?.toLowerCase().includes('ip') || ind.label?.toLowerCase().includes('domain') || ind.label?.toLowerCase().includes('c2')) {
          list.push({ ...ind, eventTitle: ev.title, timestamp: ev.timestamp });
        }
      });
    });
    return list;
  };

  const infraA = getInfraIndicators(incA);
  const infraB = getInfraIndicators(incB);

  infraA.forEach(a => {
    infraB.forEach(b => {
      const isPublic = PUBLIC_INFRA_FILTER.some(prefix => a.value.startsWith(prefix) || b.value.startsWith(prefix));

      if (a.type === b.type && a.value.toLowerCase() === b.value.toLowerCase()) {
        if (isPublic) {
          discounted.push({
            type: a.type,
            value: a.value,
            reason: 'Common CDN / Public Edge (discounted from correlation scoring)'
          });
        } else {
          matches.push({
            type: a.type,
            value: a.value,
            label: `Direct ${a.label || a.type} Overlap`,
            confidenceBonus: a.type === IndicatorTypes.DOMAIN ? 50 : 40,
            sourceA: a.eventTitle,
            sourceB: b.eventTitle
          });
        }
      } else if (a.value && b.value && a.value.includes('.') && b.value.includes('.')) {
        // Check Subnet /24 correlation for IPv4
        const partsA = a.value.split('.');
        const partsB = b.value.split('.');
        if (partsA.length === 4 && partsB.length === 4) {
          const subnetA = partsA.slice(0, 3).join('.');
          const subnetB = partsB.slice(0, 3).join('.');
          if (subnetA === subnetB && !isPublic) {
            matches.push({
              type: 'subnet_24',
              value: `${subnetA}.0/24`,
              label: 'Co-located /24 Subnet Hosting Infrastructure',
              confidenceBonus: 45,
              sourceA: a.value,
              sourceB: b.value
            });
          }
        }
      }
    });
  });

  // If Threat Intel links both incidents to the same campaign infrastructure cluster, add campaign infrastructure bonus
  if (tiResult && tiResult.attributedActor && tiResult.matchesA?.length > 0 && tiResult.matchesB?.length > 0) {
    matches.push({
      type: 'campaign_infrastructure_cluster',
      value: tiResult.attributedActor,
      label: `Attributed Threat Actor Infrastructure Cluster (${tiResult.attributedActor})`,
      confidenceBonus: 45
    });
  }

  // Calculate dimension score (0 - 100)
  const baseBonus = matches.reduce((sum, m) => sum + m.confidenceBonus, 0);
  score = Math.min(100, baseBonus);

  if (matches.length > 0) {
    rationale.push(`Identified ${matches.length} shared or co-located infrastructure indicator(s).`);
  } else {
    rationale.push('No shared C2 servers, malicious domains, or hosting subnets detected.');
  }

  if (discounted.length > 0) {
    rationale.push(`Discounted ${discounted.length} public CDN/DNS IPs to avoid false positive attribution.`);
  }

  return {
    score,
    matches,
    discounted,
    rationale: rationale.join(' ')
  };
}

/**
 * 2. Temporal & Causality Sequence Analysis
 */
function correlateTemporalSequence(incA, incB) {
  let score = 0;
  const rationale = [];
  let causalSequenceValid = false;

  const getTimestamps = (inc) => (inc.evidence || []).map(e => new Date(e.timestamp).getTime()).sort((a, b) => a - b);
  const timesA = getTimestamps(incA);
  const timesB = getTimestamps(incB);

  if (timesA.length === 0 || timesB.length === 0) {
    return { score: 0, deltaMinutes: null, causalSequenceValid: false, rationale: 'Missing timestamps for temporal correlation.' };
  }

  const startA = timesA[0];
  const startB = timesB[0];

  const deltaMs = Math.abs(startB - startA);
  const deltaMinutes = Math.round(deltaMs / (1000 * 60));
  const deltaHours = (deltaMinutes / 60).toFixed(1);

  // Causality: Mobile spyware interception preceding email login
  const isMobileFirst = startA <= startB;
  const timeDifferenceHours = (startB - startA) / (1000 * 60 * 60);

  if (isMobileFirst && timeDifferenceHours >= 0 && timeDifferenceHours <= 2) {
    // Tight sequential operational window (0 - 2 hours)
    causalSequenceValid = true;
    score = 95;
    rationale.push(`Immediate causal sequence: Mobile compromise preceded BEC mailbox takeover by ${deltaMinutes} minutes, directly consistent with real-time SMS 2FA interception.`);
  } else if (isMobileFirst && timeDifferenceHours <= 48) {
    causalSequenceValid = true;
    score = 75;
    rationale.push(`Plausible operational window: Events occurred within ${deltaHours} hours.`);
  } else if (Math.abs(timeDifferenceHours) <= 168) { // within 7 days
    score = 35;
    rationale.push(`Moderate temporal proximity: Events occurred within ${(Math.abs(timeDifferenceHours) / 24).toFixed(1)} days.`);
  } else {
    score = 10;
    rationale.push(`Weak temporal proximity: Events separated by ${(Math.abs(timeDifferenceHours) / 24).toFixed(1)} days.`);
  }

  return {
    score: Math.round(score),
    deltaMinutes,
    deltaHours,
    isMobileFirst,
    causalSequenceValid,
    startA: new Date(startA).toISOString(),
    startB: new Date(startB).toISOString(),
    rationale: rationale.join(' ')
  };
}

/**
 * 3. Identity & Asset Correlation
 */
function correlateIdentity(incA, incB) {
  const matches = [];
  let score = 0;
  let targetMatch = false;

  const getIdentityValues = (inc) => {
    const list = [];
    (inc.evidence || []).forEach(ev => {
      ev.indicators.forEach(ind => {
        if ([IndicatorTypes.ACCOUNT, IndicatorTypes.DEVICE_ID, IndicatorTypes.EMAIL_ADDR].includes(ind.type)) {
          list.push({ ...ind, title: ev.title });
        }
      });
    });
    return list;
  };

  const idA = getIdentityValues(incA);
  const idB = getIdentityValues(incB);

  idA.forEach(a => {
    idB.forEach(b => {
      const valA = a.value.toLowerCase().trim();
      const valB = b.value.toLowerCase().trim();

      const userPrefixA = valA.includes('@') ? valA.split('@')[0] : valA;
      const userPrefixB = valB.includes('@') ? valB.split('@')[0] : valB;

      if (valA === valB || (userPrefixA === userPrefixB && userPrefixA.length > 2)) {
        matches.push({
          type: 'targeted_identity',
          value: a.value,
          label: `Same Victim Identity (${a.value})`,
          bonus: 40
        });
        targetMatch = true;
      }
    });
  });

  if (targetMatch) {
    score = 90;
  } else if (matches.length > 0) {
    score = 50;
  } else {
    score = 5;
  }

  const rationale = targetMatch
    ? `Strong Identity Alignment: Both incidents specifically target the exact same employee account/device (${matches[0]?.value || 'Identity'}).`
    : `Different or unlinked identity targets across incidents.`;

  return {
    score,
    targetMatch,
    matches,
    rationale
  };
}

/**
 * 4. Artifact & IOC Matching
 */
function correlateArtifacts(incA, incB) {
  const matches = [];
  let score = 0;

  const getArtifacts = (inc) => {
    const list = [];
    (inc.evidence || []).forEach(ev => {
      ev.indicators.forEach(ind => {
        if ([IndicatorTypes.FILE_HASH, IndicatorTypes.APP_ID, IndicatorTypes.RULE_NAME].includes(ind.type)) {
          list.push(ind);
        }
      });
    });
    return list;
  };

  const artA = getArtifacts(incA);
  const artB = getArtifacts(incB);

  artA.forEach(a => {
    artB.forEach(b => {
      if (a.type === b.type && a.value.toLowerCase() === b.value.toLowerCase()) {
        matches.push({
          type: a.type,
          value: a.value,
          label: `Shared ${a.label || 'Artifact'}`,
          bonus: 40
        });
      }
    });
  });

  score = Math.min(100, matches.length * 50);
  const rationale = matches.length > 0
    ? `Identified ${matches.length} directly shared file hashes or payload identifiers.`
    : `No shared binary hashes or identical file payloads found (typical when bridging mobile OS and cloud email vectors).`;

  return {
    score,
    matches,
    rationale
  };
}

/**
 * 5. Behavioral & TTP Alignment
 */
function correlateTTPs(incA, incB) {
  const ttpsA = (incA.evidence || []).flatMap(e => e.mitreTechniques || []);
  const ttpsB = (incB.evidence || []).flatMap(e => e.mitreTechniques || []);

  const sharedTTPs = [...new Set(ttpsA.filter(t => ttpsB.includes(t)))];
  
  // Specific multi-stage synergy: Mobile Credential/MFA theft (T1636 / T1430 / T1556) leading to Enterprise Account Takeover & Mail Forwarding (T1114 / T1098 / T1078)
  const hasMobileCredentialTheft = ttpsA.some(t => ['T1636', 'T1430', 'T1556'].includes(t)) ||
                                   ttpsB.some(t => ['T1636', 'T1430', 'T1556'].includes(t));
  const hasMailboxPersistenceAndExfil = (ttpsA.some(t => ['T1114', 'T1098'].includes(t)) && ttpsA.some(t => ['T1078', 'T1556'].includes(t))) ||
                                        (ttpsB.some(t => ['T1114', 'T1098'].includes(t)) && ttpsB.some(t => ['T1078', 'T1556'].includes(t)));

  let score = 10;
  let complementaryChain = false;

  if (hasMobileCredentialTheft && hasMailboxPersistenceAndExfil) {
    complementaryChain = true;
    score = 90;
  } else if (sharedTTPs.length > 0) {
    score = 40 + sharedTTPs.length * 15;
  }

  const rationale = complementaryChain
    ? 'High Tactical Synergy: Multi-stage kill chain observed (Mobile SMS/credential theft T1636 directly facilitating Azure AD account takeover T1078 and inbox exfiltration T1114).'
    : `Behavioral patterns represent isolated, non-complementary standard operations.`;

  return {
    score: Math.min(100, score),
    sharedTTPs,
    complementaryChain,
    ttpsA: [...new Set(ttpsA)],
    ttpsB: [...new Set(ttpsB)],
    rationale
  };
}

/**
 * 6. Threat Intelligence Enrichment
 */
function correlateThreatIntelligence(incA, incB, threatIntelFeed = []) {
  const matches = [];
  const matchesA = [];
  const matchesB = [];
  let attributedActor = null;
  let score = 0;

  const getIndicators = (inc) => (inc.evidence || []).flatMap(e => e.indicators);
  const indA = getIndicators(incA);
  const indB = getIndicators(incB);

  threatIntelFeed.forEach(ti => {
    const matchInA = indA.some(i => i.value.toLowerCase() === ti.indicatorValue.toLowerCase());
    const matchInB = indB.some(i => i.value.toLowerCase() === ti.indicatorValue.toLowerCase());

    if (matchInA || matchInB) {
      const matchObj = {
        indicator: ti.indicatorValue,
        campaign: ti.campaign,
        threatActor: ti.threatActor,
        malwareFamily: ti.malwareFamily,
        confidence: ti.confidence,
        tags: ti.tags || [],
        foundIn: matchInA && matchInB ? 'both' : (matchInA ? 'incidentA' : 'incidentB')
      };

      matches.push(matchObj);
      if (matchInA) matchesA.push(matchObj);
      if (matchInB) matchesB.push(matchObj);
      if (ti.threatActor) attributedActor = ti.threatActor;
    }
  });

  // If BOTH incidents have indicators attributed to the SAME threat actor / campaign
  if (matchesA.length > 0 && matchesB.length > 0) {
    score = 95;
  } else if (matches.length > 0) {
    score = 65;
  } else {
    score = 10;
  }

  const rationale = (matchesA.length > 0 && matchesB.length > 0)
    ? `Threat Intelligence confirms BOTH incidents share infrastructure attributed to ${attributedActor || 'known adversary campaign'} (${matches[0]?.campaign}).`
    : (matches.length > 0 
      ? `Threat Intelligence matched single-vector indicator to ${attributedActor || 'known malware'}.`
      : `No matching threat actor signatures found in active threat intelligence feeds.`);

  return {
    score,
    attributedActor,
    matches,
    matchesA,
    matchesB,
    rationale
  };
}

function extractSharedEntities(incA, incB, matches) {
  const unique = new Map();
  matches.forEach(m => {
    const key = `${m.type}:${m.value || m.indicator}`;
    if (!unique.has(key)) {
      unique.set(key, {
        type: m.type,
        value: m.value || m.indicator,
        label: m.label || m.campaign || m.value,
        details: m
      });
    }
  });
  return Array.from(unique.values());
}
