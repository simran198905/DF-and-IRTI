/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Evidence Schema & Normalization Engine
 */

export const EvidenceSourceTypes = {
  MOBILE: 'mobile_device',
  EMAIL: 'corporate_email',
  IDENTITY: 'identity_auth',
  NETWORK: 'network_dns',
  SECURITY_TOOL: 'security_tool',
  THREAT_INTEL: 'threat_intel'
};

export const IndicatorTypes = {
  IP: 'ip_address',
  DOMAIN: 'domain_name',
  URL: 'url',
  FILE_HASH: 'file_hash',
  ACCOUNT: 'user_account',
  DEVICE_ID: 'device_identifier',
  EMAIL_ADDR: 'email_address',
  CERT_SERIAL: 'cert_serial',
  RULE_NAME: 'inbox_rule',
  APP_ID: 'app_package_id',
  TTP: 'mitre_ttp'
};

/**
 * Normalizes raw forensic records from various vectors into a standardized object
 */
export function normalizeEvidence(rawRecord, sourceType) {
  const timestamp = rawRecord.timestamp ? new Date(rawRecord.timestamp).toISOString() : new Date().toISOString();
  
  const baseNormalized = {
    id: rawRecord.id || `ev-${Math.random().toString(36).substr(2, 9)}`,
    incidentId: rawRecord.incidentId || 'INC-UNKNOWN',
    sourceType: sourceType || rawRecord.sourceType || EvidenceSourceTypes.SECURITY_TOOL,
    timestamp: timestamp,
    rawTimestamp: rawRecord.timestamp,
    title: rawRecord.title || 'Forensic Event',
    description: rawRecord.description || '',
    severity: rawRecord.severity || 'medium', // low, medium, high, critical
    indicators: [],
    metadata: { ...rawRecord },
    mitreTactics: rawRecord.mitreTactics || [],
    mitreTechniques: rawRecord.mitreTechniques || []
  };

  // Extract indicators based on source type
  switch (sourceType) {
    case EvidenceSourceTypes.MOBILE:
      extractMobileIndicators(rawRecord, baseNormalized);
      break;
    case EvidenceSourceTypes.EMAIL:
      extractEmailIndicators(rawRecord, baseNormalized);
      break;
    case EvidenceSourceTypes.IDENTITY:
      extractIdentityIndicators(rawRecord, baseNormalized);
      break;
    case EvidenceSourceTypes.NETWORK:
      extractNetworkIndicators(rawRecord, baseNormalized);
      break;
    case EvidenceSourceTypes.THREAT_INTEL:
      extractThreatIntelIndicators(rawRecord, baseNormalized);
      break;
    default:
      extractGenericIndicators(rawRecord, baseNormalized);
      break;
  }

  // Deduplicate indicators
  const seen = new Set();
  baseNormalized.indicators = baseNormalized.indicators.filter(ind => {
    const key = `${ind.type}:${ind.value?.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return baseNormalized;
}

function extractMobileIndicators(raw, norm) {
  if (raw.appPackage) norm.indicators.push({ type: IndicatorTypes.APP_ID, value: raw.appPackage, label: 'Package ID' });
  if (raw.deviceId || raw.imei) norm.indicators.push({ type: IndicatorTypes.DEVICE_ID, value: raw.deviceId || raw.imei, label: 'Device Identifier' });
  if (raw.destIp || raw.ip) norm.indicators.push({ type: IndicatorTypes.IP, value: raw.destIp || raw.ip, label: 'C2 IP Address' });
  if (raw.destDomain || raw.domain) norm.indicators.push({ type: IndicatorTypes.DOMAIN, value: raw.destDomain || raw.domain, label: 'C2 Domain' });
  if (raw.fileHash || raw.hash) norm.indicators.push({ type: IndicatorTypes.FILE_HASH, value: raw.fileHash || raw.hash, label: 'APK SHA256' });
  if (raw.compromisedUser || raw.user) norm.indicators.push({ type: IndicatorTypes.ACCOUNT, value: raw.compromisedUser || raw.user, label: 'Target Account' });
  if (raw.phoneNumber) norm.indicators.push({ type: IndicatorTypes.ACCOUNT, value: raw.phoneNumber, label: 'Phone Number' });
}

function extractEmailIndicators(raw, norm) {
  if (raw.senderEmail) norm.indicators.push({ type: IndicatorTypes.EMAIL_ADDR, value: raw.senderEmail, label: 'Sender Address' });
  if (raw.recipientEmail) norm.indicators.push({ type: IndicatorTypes.EMAIL_ADDR, value: raw.recipientEmail, label: 'Recipient Address' });
  if (raw.clientIp || raw.loginIp || raw.ip) norm.indicators.push({ type: IndicatorTypes.IP, value: raw.clientIp || raw.loginIp || raw.ip, label: 'Sender/Login IP' });
  if (raw.embeddedUrl) norm.indicators.push({ type: IndicatorTypes.URL, value: raw.embeddedUrl, label: 'Phishing URL' });
  if (raw.attachmentHash || raw.hash) norm.indicators.push({ type: IndicatorTypes.FILE_HASH, value: raw.attachmentHash || raw.hash, label: 'Attachment Hash' });
  if (raw.ruleForwardAddress) norm.indicators.push({ type: IndicatorTypes.EMAIL_ADDR, value: raw.ruleForwardAddress, label: 'Exfiltration Forward Target' });
  if (raw.affectedUser || raw.user) norm.indicators.push({ type: IndicatorTypes.ACCOUNT, value: raw.affectedUser || raw.user, label: 'Compromised Mailbox' });
}

function extractIdentityIndicators(raw, norm) {
  if (raw.userPrincipalName || raw.affectedUser || raw.user || raw.compromisedUser) {
    norm.indicators.push({ type: IndicatorTypes.ACCOUNT, value: raw.userPrincipalName || raw.affectedUser || raw.user || raw.compromisedUser, label: 'User Principal' });
  }
  if (raw.ipAddress || raw.loginIp || raw.ip) {
    norm.indicators.push({ type: IndicatorTypes.IP, value: raw.ipAddress || raw.loginIp || raw.ip, label: 'Sign-in IP' });
  }
  if (raw.userAgent) norm.indicators.push({ type: 'user_agent', value: raw.userAgent, label: 'Client User Agent' });
  if (raw.location) norm.indicators.push({ type: 'geo_location', value: `${raw.location.city || ''}, ${raw.location.country || ''}`, label: 'Geo Location' });
  if (raw.authMethod) norm.indicators.push({ type: 'auth_method', value: raw.authMethod, label: 'MFA Method' });
}

function extractNetworkIndicators(raw, norm) {
  if (raw.srcIp) norm.indicators.push({ type: IndicatorTypes.IP, value: raw.srcIp, label: 'Source IP' });
  if (raw.destIp || raw.ip) norm.indicators.push({ type: IndicatorTypes.IP, value: raw.destIp || raw.ip, label: 'Destination IP' });
  if (raw.domain) norm.indicators.push({ type: IndicatorTypes.DOMAIN, value: raw.domain, label: 'Queried Domain' });
  if (raw.tlsCertSha256) norm.indicators.push({ type: IndicatorTypes.CERT_SERIAL, value: raw.tlsCertSha256, label: 'TLS Cert Fingerprint' });
}

function extractThreatIntelIndicators(raw, norm) {
  if (raw.iocValue) {
    const type = raw.iocType || (raw.iocValue.includes('.') && !raw.iocValue.includes('@') ? IndicatorTypes.DOMAIN : IndicatorTypes.IP);
    norm.indicators.push({ type: type, value: raw.iocValue, label: 'Threat Intel IOC' });
  }
  if (raw.campaignName) norm.indicators.push({ type: 'campaign', value: raw.campaignName, label: 'Threat Campaign' });
  if (raw.threatActor) norm.indicators.push({ type: 'threat_actor', value: raw.threatActor, label: 'Threat Actor' });
}

function extractGenericIndicators(raw, norm) {
  if (raw.ip) norm.indicators.push({ type: IndicatorTypes.IP, value: raw.ip, label: 'IP' });
  if (raw.domain) norm.indicators.push({ type: IndicatorTypes.DOMAIN, value: raw.domain, label: 'Domain' });
  if (raw.user) norm.indicators.push({ type: IndicatorTypes.ACCOUNT, value: raw.user, label: 'User' });
  if (raw.hash) norm.indicators.push({ type: IndicatorTypes.FILE_HASH, value: raw.hash, label: 'Hash' });
}
