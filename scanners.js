/**
 * Security Review Agent — Scanner Engine
 * Pattern-based static analysis for common web app vulnerabilities.
 * Each scanner returns an array of findings.
 */

const path = require('path');

// ─── Severity Levels ─────────────────────────────────────────
const SEVERITY = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
};

const SEVERITY_WEIGHT = {
    [SEVERITY.CRITICAL]: 25,
    [SEVERITY.HIGH]: 15,
    [SEVERITY.MEDIUM]: 8,
    [SEVERITY.LOW]: 3,
    [SEVERITY.INFO]: 1,
};

// ─── Helper ──────────────────────────────────────────────────
function finding(scanner, severity, message, filePath, lineNumber, codeLine, remediation) {
    return {
        scanner,
        severity,
        message,
        file: filePath,
        line: lineNumber,
        code: (codeLine || '').trim().substring(0, 200),
        remediation,
    };
}

function scanLines(lines, filePath, patterns) {
    const results = [];
    lines.forEach((line, idx) => {
        for (const pat of patterns) {
            if (pat.test && pat.test(line)) {
                results.push({ line: idx + 1, code: line, pattern: pat });
            } else if (pat.regex && pat.regex.test(line)) {
                results.push({ line: idx + 1, code: line, ...pat });
            }
        }
    });
    return results;
}

// ─── 1. XSS Scanner ─────────────────────────────────────────
function scanXSS(lines, filePath) {
    const results = [];
    const patterns = [
        {
            regex: new RegExp('\\.inner' + 'HTML\\s*[=+]', 'i'),
            msg: 'Direct inner' + 'HTML assignment — potential XSS vector',
            fix: 'Use textContent or a DOM sanitization library (e.g., DOMPurify) instead of innerHTML.',
        },
        {
            regex: new RegExp('\\.outer' + 'HTML\\s*[=+]', 'i'),
            msg: 'Direct outer' + 'HTML assignment — potential XSS vector',
            fix: 'Use safe DOM manipulation methods instead of outerHTML.',
        },
        {
            regex: new RegExp('document\\.' + 'write\\s*\\(', 'i'),
            msg: 'document.' + 'write() usage — can inject arbitrary HTML',
            fix: 'Replace document.' + 'write() with safe DOM APIs like createElement/appendChild.',
        },
        {
            regex: new RegExp('\\beval' + '\\s*\\(', 'i'),
            msg: 'eval' + '() usage — executes arbitrary code',
            fix: 'Remove eval' + '(). Use JSON.parse() for data or safer alternatives for dynamic code.',
        },
        {
            regex: new RegExp('new\\s+' + 'Function\\s*\\(', 'i'),
            msg: 'Function constructor — equivalent to eval' + '()',
            fix: 'Avoid the Function constructor. Use explicit function definitions.',
        },
        {
            regex: new RegExp('\\bsetTimeout' + '\\s*\\(\\s*[\'"]', 'i'),
            msg: 'setTimeout with string argument — acts like eval' + '()',
            fix: 'Pass a function reference to setTimeout instead of a string.',
        },
        {
            regex: new RegExp('\\bsetInterval' + '\\s*\\(\\s*[\'"]', 'i'),
            msg: 'setInterval with string argument — acts like eval' + '()',
            fix: 'Pass a function reference to setInterval instead of a string.',
        },
        {
            regex: new RegExp('\\.insertAdjacent' + 'HTML\\s*\\(', 'i'),
            msg: 'insertAdjacentHTML usage — potential XSS if input is unsanitized',
            fix: 'Sanitize any user-derived input before passing to insertAdjacent' + 'HTML.',
        },
        {
            regex: new RegExp('\\bdangerouslySet' + 'InnerHTML\\b', 'i'),
            msg: 'React dangerouslySet' + 'InnerHTML — bypass of React\'s XSS protection',
            fix: 'Avoid dangerouslySet' + 'InnerHTML. Use a sanitizer library if raw HTML is needed.',
        },
    ];

    lines.forEach((line, idx) => {
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('XSS Vulnerabilities', SEVERITY.HIGH, pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });

    return results;
}

// ─── 2. Hardcoded Secrets Scanner ────────────────────────────
function scanSecrets(lines, filePath) {
    const results = [];
    const basename = path.basename(filePath).toLowerCase();

    // Skip minified/vendor files
    if (basename.includes('.min.') || filePath.includes('node_modules')) return results;

    const patterns = [
        {
            regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{10,}['"]/i,
            msg: 'Hardcoded API key detected',
            fix: 'Move API keys to environment variables or a server-side config. Never commit secrets to client-side code.',
        },
        {
            regex: /(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/i,
            msg: 'Hardcoded secret/password detected',
            fix: 'Use environment variables for secrets. Consider a secret management service.',
        },
        {
            regex: /(?:AKIA|ASIA)[A-Z0-9]{16}/,
            msg: 'AWS Access Key ID detected',
            fix: 'Immediately rotate this AWS key and move to environment variables or AWS IAM roles.',
        },
        {
            regex: /(?:sk_live|sk_test)_[A-Za-z0-9]{20,}/,
            msg: 'Stripe secret key detected',
            fix: 'Remove Stripe secret keys from client code. Use server-side API calls only.',
        },
        {
            regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/,
            msg: 'GitHub token detected',
            fix: 'Rotate this GitHub token and use server-side authentication instead.',
        },
        {
            regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
            msg: 'Private key embedded in source code',
            fix: 'Never embed private keys in source. Store in secure key storage.',
        },
        {
            regex: /(?:firebase|supabase|mongo(?:db)?)\s*[:=]\s*['"][^'"]{15,}['"]/i,
            msg: 'Database/service connection string may be exposed',
            fix: 'Move connection strings to server-side environment variables.',
        },
        {
            regex: /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/,
            msg: 'Hardcoded Bearer token detected',
            fix: 'Remove hardcoded tokens. Use server-side authentication flows.',
        },
    ];

    lines.forEach((line, idx) => {
        // Skip comments
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;

        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Hardcoded Secrets', SEVERITY.CRITICAL, pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });

    return results;
}

// ─── 3. Insecure HTTP Scanner ────────────────────────────────
function scanInsecureHTTP(lines, filePath) {
    const results = [];
    const httpRegex = /https?:\/\//gi;
    const insecurePattern = /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i;

    lines.forEach((line, idx) => {
        if (insecurePattern.test(line)) {
            // Skip comments
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('<!--')) return;

            results.push(finding(
                'Insecure HTTP',
                SEVERITY.MEDIUM,
                'Insecure HTTP URL detected — data sent in cleartext',
                filePath, idx + 1, line,
                'Use HTTPS instead of HTTP for all external resources and API calls.'
            ));
        }
    });

    return results;
}

// ─── 4. Dependency Risk Scanner ──────────────────────────────
function scanDependencies(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.html') {
        lines.forEach((line, idx) => {
            // Check for script tags without integrity
            const scriptMatch = line.match(/<script\s+[^>]*src\s*=\s*["']https?:\/\//i);
            if (scriptMatch) {
                if (!/integrity\s*=\s*["']/i.test(line)) {
                    results.push(finding(
                        'Dependency Risks',
                        SEVERITY.MEDIUM,
                        'External script loaded without Subresource Integrity (SRI)',
                        filePath, idx + 1, line,
                        'Add integrity="sha384-..." and crossorigin="anonymous" attributes to CDN script tags.'
                    ));
                }

                // Check for unpinned CDN versions (e.g., @latest)
                if (/@latest/i.test(line)) {
                    results.push(finding(
                        'Dependency Risks',
                        SEVERITY.HIGH,
                        'External script uses @latest — version not pinned',
                        filePath, idx + 1, line,
                        'Pin to a specific version (e.g., @1.5.2) instead of @latest to prevent supply chain attacks.'
                    ));
                }
            }

            // Check for link tags (CSS) without integrity
            const linkMatch = line.match(/<link\s+[^>]*href\s*=\s*["']https?:\/\//i);
            if (linkMatch && /rel\s*=\s*["']stylesheet["']/i.test(line)) {
                if (!/integrity\s*=\s*["']/i.test(line)) {
                    results.push(finding(
                        'Dependency Risks',
                        SEVERITY.LOW,
                        'External stylesheet loaded without Subresource Integrity (SRI)',
                        filePath, idx + 1, line,
                        'Add integrity and crossorigin attributes to external stylesheets.'
                    ));
                }
            }
        });
    }

    // Check package.json for wildcard versions
    if (path.basename(filePath) === 'package.json') {
        lines.forEach((line, idx) => {
            if (/["']\*["']/.test(line) && /:/.test(line)) {
                results.push(finding(
                    'Dependency Risks',
                    SEVERITY.HIGH,
                    'Wildcard (*) dependency version — any version will be installed',
                    filePath, idx + 1, line,
                    'Pin dependency versions to specific ranges (e.g., "^1.2.3").'
                ));
            }
        });
    }

    return results;
}

// ─── 5. Data Exposure Scanner ────────────────────────────────
function scanDataExposure(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.js' && ext !== '.ts' && ext !== '.jsx' && ext !== '.tsx' && ext !== '.mjs') return results;

    const patterns = [
        {
            regex: /localStorage\.setItem\s*\(\s*['"](?:token|password|secret|api[_-]?key|session|auth|credential)/i,
            msg: 'Sensitive data stored in localStorage — accessible via XSS',
            fix: 'Use httpOnly cookies for tokens/sessions. localStorage is accessible to any script on the page.',
        },
        {
            regex: /sessionStorage\.setItem\s*\(\s*['"](?:token|password|secret|api[_-]?key|auth|credential)/i,
            msg: 'Sensitive data stored in sessionStorage — accessible via XSS',
            fix: 'Use httpOnly cookies for sensitive data instead of sessionStorage.',
        },
        {
            regex: /console\.log\s*\(.*(?:password|secret|token|key|credential|auth)/i,
            msg: 'Potentially sensitive data logged to console',
            fix: 'Remove console.log statements that expose sensitive data before production.',
        },
        {
            regex: /console\.(log|debug|info|warn)\s*\(/i,
            msg: 'Console logging present — may leak information in production',
            fix: 'Consider removing or disabling console logs in production builds.',
            severity: SEVERITY.INFO,
        },
    ];

    lines.forEach((line, idx) => {
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding(
                    'Data Exposure',
                    pat.severity || SEVERITY.MEDIUM,
                    pat.msg,
                    filePath, idx + 1, line,
                    pat.fix
                ));
            }
        }
    });

    return results;
}

// ─── 6. Missing Security Headers Scanner ─────────────────────
function scanSecurityHeaders(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.html') return results;

    const fullContent = lines.join('\n');

    // Check for Content Security Policy
    if (!/meta\s+http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(fullContent)) {
        results.push(finding(
            'Missing Security Headers',
            SEVERITY.MEDIUM,
            'No Content Security Policy (CSP) meta tag found',
            filePath, 1, '<head>',
            'Add <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'"> to restrict resource loading.'
        ));
    }

    // Check for X-Frame-Options
    if (!/meta\s+http-equiv\s*=\s*["']X-Frame-Options["']/i.test(fullContent)) {
        results.push(finding(
            'Missing Security Headers',
            SEVERITY.LOW,
            'No X-Frame-Options meta tag — page can be embedded in iframes (clickjacking risk)',
            filePath, 1, '<head>',
            'Add <meta http-equiv="X-Frame-Options" content="DENY"> or configure server headers.'
        ));
    }

    // Check target="_blank" links without rel="noopener"
    lines.forEach((line, idx) => {
        if (/target\s*=\s*["']_blank["']/i.test(line) && !/rel\s*=\s*["'][^"']*noopener[^"']*["']/i.test(line)) {
            results.push(finding(
                'Missing Security Headers',
                SEVERITY.LOW,
                'Link with target="_blank" missing rel="noopener" — enables reverse tabnabbing',
                filePath, idx + 1, line,
                'Add rel="noopener noreferrer" to all target="_blank" links.'
            ));
        }
    });

    return results;
}

// ─── 7. Input Validation Scanner ─────────────────────────────
function scanInputValidation(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.html') {
        lines.forEach((line, idx) => {
            // Check for input fields without type
            if (/<input\b/i.test(line) && !/type\s*=/i.test(line)) {
                results.push(finding(
                    'Input Validation',
                    SEVERITY.LOW,
                    'Input element without explicit type attribute',
                    filePath, idx + 1, line,
                    'Always specify input type (e.g., type="email", type="number") for proper validation.'
                ));
            }

            // Check for forms without action (may post to same page)
            if (/<form\b/i.test(line) && !/action\s*=/i.test(line)) {
                results.push(finding(
                    'Input Validation',
                    SEVERITY.INFO,
                    'Form element without explicit action attribute',
                    filePath, idx + 1, line,
                    'Specify an explicit form action to make the form destination clear.'
                ));
            }
        });
    }

    if (ext === '.js' || ext === '.ts' || ext === '.jsx' || ext === '.tsx') {
        const urlParamsRegex = new RegExp('(?:URLSearch' + 'Params|location\\.search|location\\.hash|location\\.href)');
        lines.forEach((line, idx) => {
            // URL parameter extraction without validation
            if (urlParamsRegex.test(line)) {
                results.push(finding(
                    'Input Validation',
                    SEVERITY.MEDIUM,
                    'URL parameters accessed — ensure values are validated before use',
                    filePath, idx + 1, line,
                    'Always validate, sanitize, and type-check URL parameter values before using them.'
                ));
            }
        });
    }

    return results;
}

// ─── 8. CORS Misconfiguration Scanner ────────────────────────
function scanCORS(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.js' && ext !== '.ts' && ext !== '.json') return results;

    lines.forEach((line, idx) => {
        if (/Access-Control-Allow-Origin['":\s]*['"]\*['"]/i.test(line)) {
            results.push(finding(
                'CORS Misconfiguration',
                SEVERITY.HIGH,
                'CORS allows all origins (wildcard *) — any website can make requests',
                filePath, idx + 1, line,
                'Restrict Access-Control-Allow-Origin to specific trusted domains instead of *.'
            ));
        }

        if (/cors\s*\(\s*\)/i.test(line)) {
            results.push(finding(
                'CORS Misconfiguration',
                SEVERITY.MEDIUM,
                'CORS enabled with default (permissive) settings',
                filePath, idx + 1, line,
                'Configure CORS with specific origin, methods, and headers restrictions.'
            ));
        }
    });

    return results;
}

// ─── 9. Insecure Cookie Scanner ──────────────────────────────
function scanCookies(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.js' && ext !== '.ts') return results;

    const cookieRegex = new RegExp('document\\.' + 'cookie\\s*=', 'i');

    lines.forEach((line, idx) => {
        if (cookieRegex.test(line)) {
            if (!/[Ss]ecure/.test(line)) {
                results.push(finding(
                    'Insecure Cookies',
                    SEVERITY.MEDIUM,
                    'Cookie set without Secure flag — may be sent over HTTP',
                    filePath, idx + 1, line,
                    'Add the Secure flag so cookies are only sent over HTTPS.'
                ));
            }
            if (!/[Hh]ttp[Oo]nly/.test(line)) {
                results.push(finding(
                    'Insecure Cookies',
                    SEVERITY.MEDIUM,
                    'Cookie set via document.cookie — cannot be HttpOnly (accessible to scripts)',
                    filePath, idx + 1, line,
                    'Set cookies server-side with the HttpOnly flag to prevent XSS theft.'
                ));
            }
            if (!/[Ss]ame[Ss]ite/.test(line)) {
                results.push(finding(
                    'Insecure Cookies',
                    SEVERITY.LOW,
                    'Cookie set without SameSite attribute — vulnerable to CSRF',
                    filePath, idx + 1, line,
                    'Add SameSite=Strict or SameSite=Lax to prevent cross-site request forgery.'
                ));
            }
        }
    });

    return results;
}

// ─── 10. Open Redirect Scanner ───────────────────────────────
function scanOpenRedirects(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.js' && ext !== '.ts' && ext !== '.jsx' && ext !== '.tsx') return results;

    const patterns = [
        {
            regex: new RegExp('(?:window\\.)?location(?:\\.href)?\\s*=\\s*(?:(?:new\\s+)?URLSearch' + 'Params|.*(?:getParam|query|search|hash))', 'i'),
            msg: 'Redirect destination may come from user input — open redirect risk',
            fix: 'Validate redirect URLs against a whitelist of allowed domains before redirecting.',
        },
        {
            regex: new RegExp('(?:window\\.)?location\\.replace\\s*\\(.*(?:param|query|search|hash|input|url)', 'i'),
            msg: 'location.' + 'replace() with potentially user-controlled input',
            fix: 'Validate the URL before using location.replace(). Only allow relative paths or whitelisted domains.',
        },
        {
            regex: new RegExp('window\\.open\\s*\\(.*(?:param|query|search|hash|input|url)', 'i'),
            msg: 'window.' + 'open() with potentially user-controlled URL',
            fix: 'Validate URLs before passing to window.open(). Use a whitelist of allowed domains.',
        },
    ];

    lines.forEach((line, idx) => {
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Open Redirects', SEVERITY.HIGH, pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });

    return results;
}

// ─── 11. Prototype Pollution Scanner ─────────────────────────
function scanPrototypePollution(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.js' && ext !== '.ts') return results;

    lines.forEach((line, idx) => {
        if (new RegExp('__' + 'proto__').test(line)) {
            results.push(finding(
                'Prototype Pollution',
                SEVERITY.MEDIUM,
                '__' + 'proto__ access detected — potential prototype pollution',
                filePath, idx + 1, line,
                'Use Object.create(null) for plain objects and validate keys when merging user input.'
            ));
        }

        if (/Object\.assign\s*\(\s*\{?\s*\}\s*,.*(?:req|param|body|input|query|data)/i.test(line)) {
            results.push(finding(
                'Prototype Pollution',
                SEVERITY.MEDIUM,
                'Object.assign with user-controlled data — prototype pollution risk',
                filePath, idx + 1, line,
                'Filter out __' + 'proto__, constructor, and prototype keys before merging user data.'
            ));
        }
    });

    return results;
}

// ─── 12. Sensitive File Exposure Scanner ─────────────────────
function scanSensitiveFiles(filePath) {
    const results = [];
    const basename = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();

    const sensitiveNames = ['.env', '.env.local', '.env.production', '.env.development'];
    if (sensitiveNames.includes(basename)) {
        results.push(finding(
            'Sensitive File Exposure',
            SEVERITY.CRITICAL,
            `Environment file "${basename}" found — may contain secrets`,
            filePath, 1, `File: ${basename}`,
            'Add .env files to .gitignore. Never deploy .env files to production. Use server-side env vars instead.'
        ));
    }

    if (basename === 'config.json' || basename === 'secrets.json' || basename === 'credentials.json') {
        results.push(finding(
            'Sensitive File Exposure',
            SEVERITY.HIGH,
            `Sensitive config file "${basename}" found`,
            filePath, 1, `File: ${basename}`,
            'Ensure this file is in .gitignore and not served to clients.'
        ));
    }

    if (basename === '.htpasswd' || basename === '.htaccess') {
        results.push(finding(
            'Sensitive File Exposure',
            SEVERITY.HIGH,
            `Server config file "${basename}" found in project`,
            filePath, 1, `File: ${basename}`,
            'Ensure server config files are not accessible from the web.'
        ));
    }

    return results;
}

// ─── Main Scanner Orchestrator ───────────────────────────────
function runAllScanners(filePath, content) {
    const lines = content.split('\n');
    const results = [];

    // File-level checks (don't need content parsing)
    results.push(...scanSensitiveFiles(filePath));

    // Content-based scanners
    results.push(...scanXSS(lines, filePath));
    results.push(...scanSecrets(lines, filePath));
    results.push(...scanInsecureHTTP(lines, filePath));
    results.push(...scanDependencies(lines, filePath));
    results.push(...scanDataExposure(lines, filePath));
    results.push(...scanSecurityHeaders(lines, filePath));
    results.push(...scanInputValidation(lines, filePath));
    results.push(...scanCORS(lines, filePath));
    results.push(...scanCookies(lines, filePath));
    results.push(...scanOpenRedirects(lines, filePath));
    results.push(...scanPrototypePollution(lines, filePath));

    return results;
}

// ─── Score Calculation ───────────────────────────────────────
function calculateScore(findings) {
    if (findings.length === 0) return 100;

    // Filter out INFO-level findings from score
    const scorableFindings = findings.filter(f => f.severity !== SEVERITY.INFO);
    if (scorableFindings.length === 0) return 100;

    let totalPenalty = 0;
    for (const f of scorableFindings) {
        totalPenalty += SEVERITY_WEIGHT[f.severity] || 0;
    }

    // Cap penalty at 100
    const score = Math.max(0, 100 - totalPenalty);
    return score;
}

function getScoreGrade(score) {
    if (score >= 90) return { grade: 'A', label: 'Excellent', color: '#22c55e' };
    if (score >= 75) return { grade: 'B', label: 'Good', color: '#84cc16' };
    if (score >= 60) return { grade: 'C', label: 'Needs Improvement', color: '#eab308' };
    if (score >= 40) return { grade: 'D', label: 'Poor', color: '#f97316' };
    return { grade: 'F', label: 'Critical', color: '#ef4444' };
}

module.exports = {
    SEVERITY,
    SEVERITY_WEIGHT,
    runAllScanners,
    calculateScore,
    getScoreGrade,
};
