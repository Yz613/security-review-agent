const fs = require('fs');

const auditLog = {
  "index.html:20:Dependency Risks": {
    "scanner": "Dependency Risks",
    "severity": "medium",
    "message": "External script loaded without Subresource Integrity (SRI)",
    "file": "index.html",
    "line": 20,
    "code": "<script src=\"https://unpkg.com/peerjs@1.5.2/dist/peerjs.min.js\"",
    "remediation": "Add integrity...",
    "status": "OPEN",
    "firstSeen": "2026-02-24T22:16:21.157Z"
  }
};

const allFindings = [];

let newResolvedCount = 0;
const currentFindingKeys = new Set(allFindings.map(f => `${f.file}:${f.line}:${f.scanner}`));

for (const key in auditLog) {
    if (auditLog[key].status === 'OPEN' && !currentFindingKeys.has(key)) {
        auditLog[key].status = 'RESOLVED';
        auditLog[key].resolvedAt = new Date().toISOString();
        newResolvedCount++;
        auditLog[key].fixApplied = '<script src="test.js"></script>';
    }
}

const completeAuditTrail = Object.values(auditLog);
if (newResolvedCount > 0) {
    console.log(`\n🎉 Great job! You resolved ${newResolvedCount} issue(s) since the last scan!`);
    const justResolved = completeAuditTrail.filter(f => f.status === 'RESOLVED' && f.resolvedAt && (new Date() - new Date(f.resolvedAt) < 10000));
    console.log('justResolved length:', justResolved.length);
    justResolved.forEach((f, i) => {
        console.log(`  ${i + 1}. [RESOLVED] ${f.message}`);
        console.log(`     File: ${f.file}:${f.line}`);
        console.log(`     Fix Applied : ${f.fixApplied.trim()}`);
    });
}
