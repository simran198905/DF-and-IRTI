/**
 * Cross-Vector Forensic and Threat Intelligence Correlation Framework
 * Pre-configured Real-World Inspired Benchmark Scenarios
 */

import { EvidenceSourceTypes, normalizeEvidence } from '../models/evidenceSchema.js';

export const THREAT_INTEL_FEEDS = [
  {
    indicatorValue: 'c2-relay.cloud-telemetry-cdn.com',
    iocType: 'domain_name',
    campaign: 'Operation DoubleFalcon (Targeted Executive Surveillance & Wire Fraud)',
    threatActor: 'APT-MANTIS / SilverTerrier Cluster',
    malwareFamily: 'Hermit / Predator Mobile Variant + BEC PhishKit',
    confidence: 'High',
    tags: ['Targeted BEC', 'Mobile Spyware', 'SMS Stealer', 'OAuth Abuse']
  },
  {
    indicatorValue: '198.51.100.44',
    iocType: 'ip_address',
    campaign: 'Operation DoubleFalcon',
    threatActor: 'APT-MANTIS / SilverTerrier Cluster',
    malwareFamily: 'C2 Command Relay Node',
    confidence: 'High',
    tags: ['C2 Server', 'Fast Flux Hosting']
  },
  {
    indicatorValue: '198.51.100.47',
    iocType: 'ip_address',
    campaign: 'Operation DoubleFalcon',
    threatActor: 'APT-MANTIS / SilverTerrier Cluster',
    malwareFamily: 'Adversary-in-the-Middle (AiTM) Proxy',
    confidence: 'High',
    tags: ['AiTM Proxy', 'Session Hijacking']
  },
  {
    indicatorValue: 'syn-srv9.dynamic-dns-zone.net',
    iocType: 'domain_name',
    campaign: 'Operation GhostPulse',
    threatActor: 'Volt Typhoon Secondary Cluster',
    malwareFamily: 'GhostPulse Stealer',
    confidence: 'Medium',
    tags: ['Credential Stealer', 'Source Code Access']
  }
];

export const SAMPLE_CASES = [
  {
    id: 'CASE-001-COORDINATED',
    title: 'Operation DoubleFalcon: Mobile Spyware + CFO BEC Campaign',
    subtitle: 'Coordinated Attack: Mobile SMS MFA interception directly preceding corporate mailbox takeover',
    expectedGroundTruth: 'HIGH',
    description: 'A critical multi-vector incident involving CFO Sarah Chen. Forensic triage discovered an MDM-managed iPhone compromised by commercial surveillance spyware that intercepted SMS 2FA tokens, immediately followed 18 minutes later by an unauthorized Microsoft 365 login from co-located adversary infrastructure, creating malicious inbox rules and initiating a fraudulent $420,000 wire payment.',
    incidents: [
      {
        id: 'INC-2026-MOB-089',
        title: 'Incident 1: Mobile Device Surveillance Spyware (CFO Asset)',
        vectorType: 'Organization-Managed Mobile Device (iOS/MDM)',
        asset: 'iPhone 15 Pro (IMEI: 358921098412345)',
        targetedUser: 'sarah.chen@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-mob-01',
            incidentId: 'INC-2026-MOB-089',
            title: 'Suspicious Zero-Click Message Artifact & WebKit Exploit',
            timestamp: '2026-08-20T08:14:22Z',
            severity: 'critical',
            compromisedUser: 'sarah.chen@acme-corp.com',
            deviceId: 'IMEI-358921098412345',
            phoneNumber: '+1-415-555-0182',
            description: 'Syslog analysis indicates anomalous WebKit daemon crash following silent binary SMS payload reception.',
            mitreTactics: ['Initial Access', 'Execution'],
            mitreTechniques: ['T1430', 'T1437']
          }, EvidenceSourceTypes.MOBILE),
          normalizeEvidence({
            id: 'ev-mob-02',
            incidentId: 'INC-2026-MOB-089',
            title: 'Spyware Payload Dropped & Persistence Established',
            timestamp: '2026-08-20T08:16:05Z',
            severity: 'critical',
            fileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            appPackage: 'com.apple.mdm.telemetry.svc (Spoofed)',
            description: 'Hidden daemon installed in sandbox with accessibility and SMS interception entitlements.',
            mitreTactics: ['Persistence', 'Privilege Escalation'],
            mitreTechniques: ['T1636', 'T1402']
          }, EvidenceSourceTypes.MOBILE),
          normalizeEvidence({
            id: 'ev-mob-03',
            incidentId: 'INC-2026-MOB-089',
            title: 'Encrypted C2 Beaconing & SMS Interception Logged',
            timestamp: '2026-08-20T08:19:40Z',
            severity: 'critical',
            destIp: '198.51.100.44',
            destDomain: 'c2-relay.cloud-telemetry-cdn.com',
            description: 'Outbound TLS 1.3 socket established to adversary C2 relay; exfiltrating device SMS 2FA passcode.',
            mitreTactics: ['Collection', 'Command and Control'],
            mitreTechniques: ['T1636', 'T1437']
          }, EvidenceSourceTypes.MOBILE)
        ]
      },
      {
        id: 'INC-2026-BEC-042',
        title: 'Incident 2: Microsoft 365 Corporate Mailbox Takeover & Wire Fraud',
        vectorType: 'Corporate Email & Identity (O365 / Azure AD)',
        asset: 'Exchange Online (sarah.chen@acme-corp.com)',
        targetedUser: 'sarah.chen@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-bec-01',
            incidentId: 'INC-2026-BEC-042',
            title: 'Unauthorized Azure AD Sign-in via Intercepted SMS MFA',
            timestamp: '2026-08-20T08:32:15Z',
            severity: 'critical',
            affectedUser: 'sarah.chen@acme-corp.com',
            loginIp: '198.51.100.47',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0',
            description: 'Adversary signed into CFO corporate mailbox from IP 198.51.100.47 (same /24 subnet as mobile C2 relay 198.51.100.44) using valid SMS token.',
            mitreTactics: ['Initial Access', 'Defense Evasion'],
            mitreTechniques: ['T1556', 'T1078']
          }, EvidenceSourceTypes.EMAIL),
          normalizeEvidence({
            id: 'ev-bec-02',
            incidentId: 'INC-2026-BEC-042',
            title: 'Malicious Inbox Hidden Forwarding Rule Created',
            timestamp: '2026-08-20T08:36:50Z',
            severity: 'high',
            affectedUser: 'sarah.chen@acme-corp.com',
            ruleForwardAddress: 'finance-audit@invoicing-gateways.com',
            description: 'Exchange rule "..." created to auto-delete incoming emails containing keywords "wire", "invoice", "urgent" and forward copies externally.',
            mitreTactics: ['Persistence', 'Collection'],
            mitreTechniques: ['T1114', 'T1098']
          }, EvidenceSourceTypes.EMAIL),
          normalizeEvidence({
            id: 'ev-bec-03',
            incidentId: 'INC-2026-BEC-042',
            title: 'Spoofed CEO Urgent Acquisition Payment Email Transmitted',
            timestamp: '2026-08-20T08:44:10Z',
            severity: 'critical',
            senderEmail: 'sarah.chen@acme-corp.com',
            recipientEmail: 'controller@acme-corp.com',
            description: 'Adversary initiated unauthorized $420,000 international acquisition wire instruction to foreign bank.',
            mitreTactics: ['Impact', 'Exfiltration'],
            mitreTechniques: ['T1566', 'T1020']
          }, EvidenceSourceTypes.EMAIL)
        ]
      }
    ]
  },
  {
    id: 'CASE-002-INDEPENDENT',
    title: 'Unrelated Coincidental Alerts: Adware App vs Standard Phishing Spam',
    subtitle: 'Independent Incidents: Marketing employee installed torch app while generic spray spam occurred',
    expectedGroundTruth: 'LOW',
    description: 'An employee downloaded a suspicious free flashlight utility from a third-party store containing aggressive ad-tracking code. Around the same time, the employee received a generic automated FedEx parcel delivery spam phish. Despite targeting the same user, forensic cross-correlation proves both attacks share zero malicious infrastructure, have unrelated TTPs, and are entirely independent.',
    incidents: [
      {
        id: 'INC-2026-MOB-112',
        title: 'Incident 1: Low-Risk Adware / Tracking Application on BYOD Device',
        vectorType: 'Mobile Device (Android)',
        asset: 'Samsung Galaxy S23 (IMEI: 351239847192837)',
        targetedUser: 'alex.rivera@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-ind-mob-01',
            incidentId: 'INC-2026-MOB-112',
            title: 'Adware App Installed (Flashlight Torch Pro)',
            timestamp: '2026-08-21T11:00:00Z',
            severity: 'low',
            appPackage: 'com.superbright.flashlight.torch',
            compromisedUser: 'alex.rivera@acme-corp.com',
            description: 'Side-loaded APK requesting coarse location and background ad-serving permissions.',
            mitreTactics: ['Execution'],
            mitreTechniques: ['T1437']
          }, EvidenceSourceTypes.MOBILE),
          normalizeEvidence({
            id: 'ev-ind-mob-02',
            incidentId: 'INC-2026-MOB-112',
            title: 'Ad-Network Telemetry Beacon (Cloudflare CDN)',
            timestamp: '2026-08-21T11:05:00Z',
            severity: 'low',
            destIp: '104.18.22.11',
            destDomain: 'ads.global-ad-exchange-network.com',
            description: 'Standard ad telemetry over public Cloudflare CDN edges.',
            mitreTactics: ['Command and Control'],
            mitreTechniques: ['T1437']
          }, EvidenceSourceTypes.MOBILE)
        ]
      },
      {
        id: 'INC-2026-EML-301',
        title: 'Incident 2: Commodity Phishing Email (FedEx Spoof)',
        vectorType: 'Corporate Email Gateway',
        asset: 'Secure Email Gateway (alex.rivera@acme-corp.com)',
        targetedUser: 'alex.rivera@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-ind-eml-01',
            incidentId: 'INC-2026-EML-301',
            title: 'Automated Fake Delivery Notice Blocked',
            timestamp: '2026-08-21T15:40:00Z',
            severity: 'low',
            affectedUser: 'alex.rivera@acme-corp.com',
            senderEmail: 'tracking-update@parcel-delivery-express.top',
            clientIp: '105.112.45.12',
            embeddedUrl: 'http://parcel-delivery-express.top/login.php',
            description: 'Mass-blast phishing attempt sent from residential botnet; quarantined by gateway.',
            mitreTactics: ['Initial Access'],
            mitreTechniques: ['T1566']
          }, EvidenceSourceTypes.EMAIL)
        ]
      }
    ]
  },
  {
    id: 'CASE-003-AMBIGUOUS',
    title: 'Operation GhostPulse: Shared Hosting Infrastructure with 12-Day Lag',
    subtitle: 'Medium Confidence: Subnet correlation and developer target overlap with temporal lag',
    expectedGroundTruth: 'MEDIUM',
    description: 'Forensic team detected a mobile credential stealer on a Principal DevOps Engineer device. Twelve days later, an unauthorized API token access attempt on the corporate Azure DevOps instance originated from a co-located hosting provider ASN. While the target and hosting provider overlap, the 12-day delay and generic stealer footprint introduce plausible alternative hypotheses.',
    incidents: [
      {
        id: 'INC-2026-MOB-177',
        title: 'Incident 1: Infostealer Infiltration on Engineering Lead Mobile',
        vectorType: 'Mobile Device (Pixel 8)',
        asset: 'Google Pixel 8 (IMEI: 357891230491823)',
        targetedUser: 'devops-lead@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-amb-01',
            incidentId: 'INC-2026-MOB-177',
            title: 'Malicious Developer Utility Installed',
            timestamp: '2026-08-08T09:12:00Z',
            severity: 'high',
            compromisedUser: 'devops-lead@acme-corp.com',
            destIp: '203.0.113.88',
            destDomain: 'syn-srv9.dynamic-dns-zone.net',
            description: 'Trojanized SSH key management utility beaconing to dynamic DNS endpoint.',
            mitreTactics: ['Initial Access', 'Credential Access'],
            mitreTechniques: ['T1437', 'T1636']
          }, EvidenceSourceTypes.MOBILE)
        ]
      },
      {
        id: 'INC-2026-API-099',
        title: 'Incident 2: Anomalous Azure DevOps Personal Access Token Usage',
        vectorType: 'Corporate Identity & Code Repository',
        asset: 'Azure DevOps (devops-lead@acme-corp.com)',
        targetedUser: 'devops-lead@acme-corp.com',
        evidence: [
          normalizeEvidence({
            id: 'ev-amb-02',
            incidentId: 'INC-2026-API-099',
            title: 'Repository Clone via Harvested PAT',
            timestamp: '2026-08-20T14:20:00Z',
            severity: 'high',
            affectedUser: 'devops-lead@acme-corp.com',
            loginIp: '203.0.113.91',
            description: 'Automated repository clone attempt originating from 203.0.113.91 (same /24 hosting range as mobile C2 endpoint).',
            mitreTactics: ['Exfiltration'],
            mitreTechniques: ['T1114', 'T1020']
          }, EvidenceSourceTypes.IDENTITY)
        ]
      }
    ]
  }
];
