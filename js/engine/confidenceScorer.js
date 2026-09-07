/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Explainable Confidence Assessment Engine
 */

export const ConfidenceLevels = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH'
};

const DIMENSION_WEIGHTS = {
  infrastructure: 0.25,
  temporal: 0.20,
  identity: 0.15,
  behavioralTTP: 0.15,
  threatIntelligence: 0.15,
  artifacts: 0.10
};

/**
 * Calculates final correlation confidence level, explainable score, and evidence matrix
 */
export function calculateAttributionConfidence(correlationResult) {
  if (!correlationResult || !correlationResult.dimensions) {
    return {
      level: ConfidenceLevels.LOW,
      score: 0,
      verdict: 'Insufficient Data',
      breakdown: []
    };
  }

  const { dimensions } = correlationResult;
  let weightedScore = 0;
  const breakdown = [];
  let strongDimensionsCount = 0;

  // 1. Calculate weighted scores
  Object.keys(DIMENSION_WEIGHTS).forEach(dimKey => {
    const dim = dimensions[dimKey];
    const weight = DIMENSION_WEIGHTS[dimKey];
    const rawScore = dim ? dim.score || 0 : 0;
    const contribution = Math.round(rawScore * weight);
    weightedScore += contribution;

    if (rawScore >= 70) {
      strongDimensionsCount++;
    }

    breakdown.push({
      dimension: dimKey,
      displayName: formatDimensionName(dimKey),
      rawScore,
      weightPercentage: Math.round(weight * 100),
      contribution,
      rationale: dim?.rationale || 'No correlation observed.',
      matches: dim?.matches || []
    });
  });

  // Check critical anchor rules:
  // An attack cannot be deemed "HIGH" or "MEDIUM" confidence based SOLELY on targeting the same user if there is zero shared infrastructure, zero threat intel overlap, and no tactical chain.
  const infraScore = dimensions.infrastructure?.score || 0;
  const tiScore = dimensions.threatIntelligence?.score || 0;
  const ttpScore = dimensions.behavioralTTP?.score || 0;
  const temporalScore = dimensions.temporal?.score || 0;

  let confidenceLevel = ConfidenceLevels.LOW;
  let verdictSummary = '';
  let narrativeExplanation = '';
  let counterHypothesis = '';

  const hasTechnicalNexus = infraScore >= 40 || tiScore >= 60;
  const hasStrongCausality = dimensions.temporal?.causalSequenceValid && temporalScore >= 70;

  if (weightedScore >= 70 && strongDimensionsCount >= 3 && (hasTechnicalNexus || hasStrongCausality)) {
    confidenceLevel = ConfidenceLevels.HIGH;
    verdictSummary = 'High Confidence: Coordinated Multi-Vector Attack Campaign';
    narrativeExplanation = 'Several independent forensic evidence sources strongly support a unified, coordinated attack campaign. Observed sequential progression from initial mobile asset compromise directly into corporate email unauthorized access, reinforced by shared threat intelligence infrastructure.';
    counterHypothesis = 'Unlikely to be independent events given the multi-vector infrastructure congruence, causal temporal sequence, and targeted adversary intelligence.';
  } else if ((weightedScore >= 35 && hasTechnicalNexus) || (weightedScore >= 40 && strongDimensionsCount >= 2)) {
    confidenceLevel = ConfidenceLevels.MEDIUM;
    verdictSummary = 'Medium Confidence: Probable Correlated Incidents';
    narrativeExplanation = 'Multiple relevant similarities exist across vectors (e.g., shared hosting subnets or threat campaign overlap), but alternative explanations remain plausible (such as temporal separation or independent exploitation of the same target).';
    counterHypothesis = 'Possibility of coincidental timing, shared generic hosting infrastructure, or commodity opportunistic malware acting independently on the same target.';
  } else {
    confidenceLevel = ConfidenceLevels.LOW;
    verdictSummary = 'Low Confidence: Independent Incidents (Coincidental)';
    narrativeExplanation = 'Few or weak similarities detected across vectors. While individual alerts occurred on the same corporate entity, the complete lack of shared C2 infrastructure, unlinked malware families, and standard non-synergistic activity indicate independent security events.';
    counterHypothesis = 'Forensic indicators demonstrate distinct origins, unlinked attack infrastructure, and lack of tactical progression between events.';
  }

  return {
    level: confidenceLevel,
    score: Math.min(100, Math.round(weightedScore)),
    verdict: verdictSummary,
    explanation: narrativeExplanation,
    counterHypothesis,
    strongDimensionsCount,
    breakdown,
    recommendedActions: generateRecommendations(confidenceLevel, correlationResult)
  };
}

function formatDimensionName(key) {
  const names = {
    infrastructure: 'Infrastructure & C2 Overlap',
    temporal: 'Temporal Sequence & Causality',
    identity: 'Target Identity & Account Alignment',
    behavioralTTP: 'Behavioral & MITRE ATT&CK TTPs',
    threatIntelligence: 'Threat Intelligence & Campaign Intel',
    artifacts: 'Artifact & Binary Hash Matches'
  };
  return names[key] || key;
}

function generateRecommendations(level, result) {
  const actions = [];
  if (level === ConfidenceLevels.HIGH) {
    actions.push('Immediately isolate the compromised mobile device via MDM / EDR quarantine.');
    actions.push('Revoke all active Azure AD / Okta SSO tokens and force password reset + hardware MFA re-enrollment for affected identity.');
    actions.push('Audit and purge malicious inbox forwarding rules and newly registered OAuth enterprise applications.');
    actions.push('Block all identified C2 IPs and domain infrastructure at perimeter firewalls and DNS sinkholes.');
    actions.push('Initiate organization-wide hunt for identical MITRE TTPs across other VIP mailboxes.');
  } else if (level === ConfidenceLevels.MEDIUM) {
    actions.push('Request deep mobile triage logs (sysdiagnose / MVT mobile verification toolkit) to confirm persistence mechanism.');
    actions.push('Perform retroactive DNS and NetFlow query hunt for secondary C2 domains across organization.');
    actions.push('Monitor targeted employee mailbox for anomalous API-driven graph read/export events.');
    actions.push('Correlate external threat intelligence feeds for newly registered domains under matching ASN.');
  } else {
    actions.push('Close cross-correlation ticket as Independent Incidents.');
    actions.push('Continue standard isolated DFIR triage for the individual mobile malware alert.');
    actions.push('Standard email phishing remediation (quarantine email, reset password).');
  }
  return actions;
}
