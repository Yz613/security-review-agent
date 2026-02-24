const fs = require('fs');

const rawFindings = [{
    "scanner": "Dependency Risks",
    "severity": "medium",
    "message": "External script loaded without Subresource Integrity (SRI)",
    "file": "index.html",
    "line": 20,
    "code": "<script src=\"https://unpkg.com/peerjs@1.5.2/dist/peerjs.min.js\"",
    "remediation": "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" attributes to CDN script tags.",
    "status": "RESOLVED",
    "firstSeen": "2026-02-24T22:16:21.157Z",
    "resolvedAt": "2026-02-24T22:16:40.450Z",
    "fixApplied": "<script src=\"test.js\"></script>"
}];

const headers = ['Status', 'Severity', 'Category', 'File', 'Line', 'Issue', 'Fix Suggestion', 'Fix Applied'];
const escapeCSV = (str) => {
    if (str == null) return '""';
    const s = String(str).replace(/"/g, '""');
    return '"' + s + '"';
};

const rows = rawFindings.map(f => [
    escapeCSV(f.status || 'OPEN'),
    escapeCSV(f.severity.toUpperCase()),
    escapeCSV(f.scanner),
    escapeCSV(f.file),
    escapeCSV(f.line),
    escapeCSV(f.message),
    escapeCSV(f.remediation),
    escapeCSV(f.fixApplied || '')
].join(','));

console.log(headers.join(','));
console.log(rows.join('\n'));
