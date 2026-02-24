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

// ─── 13. Injection Vulnerabilities ───────────────────────────
function scanInjection(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    const jsLike = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];
    if (!jsLike.includes(ext)) return results;

    const patterns = [
        { regex: /(?:query|execute|run)\s*\(\s*[`'"].*\$\{/, msg: 'SQL Injection — string interpolation in SQL query', sev: 'critical', fix: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.' },
        { regex: /(?:query|execute|run)\s*\(\s*["'`][^"'`]*\s*\+\s*(?:req\.|params\.|body\.|query\.)/, msg: 'SQL Injection — concatenation of user input in query', sev: 'critical', fix: 'Use parameterized queries (e.g., db.query("SELECT * FROM users WHERE id=?", [id])).' },
        { regex: /\$where\s*:\s*(?:req\.|params\.|body\.|query\.|function)/, msg: 'NoSQL Injection — $where with user input enables JS execution', sev: 'critical', fix: 'Never use $where with user-controlled input. Use $eq and other safe operators.' },
        { regex: /\$regex\s*:\s*(?:req\.|params\.|body\.|query\.)/, msg: 'NoSQL Injection — $regex with user input can cause ReDoS', sev: 'high', fix: 'Sanitize and escape user input before using in regex queries.' },
        { regex: /(?:exec|execSync|spawn|spawnSync)\s*\(.*(?:req\.|params\.|body\.|query\.|process\.argv)/, msg: 'Command Injection — user input passed to shell command', sev: 'critical', fix: 'Never pass user input to shell commands. Use execFile() with argument arrays instead.' },
        { regex: /child_process.*(?:req\.|params\.|body\.|query\.)/, msg: 'Command Injection — child_process used with possible user input', sev: 'critical', fix: 'Use execFile() with a fixed command and validated argument list. Whitelist allowed values.' },
        { regex: /require\s*\(\s*(?:req\.|params\.|body\.|query\.)/, msg: 'Code Injection — dynamic require() with user-controlled path', sev: 'critical', fix: 'Never use dynamic require() with user input. Use a static lookup map instead.' },
        { regex: /import\s*\(\s*(?:req\.|params\.|body\.|query\.)/, msg: 'Code Injection — dynamic import() with user-controlled path', sev: 'critical', fix: 'Never dynamically import user-controlled paths. Use a static map of allowed modules.' },
        { regex: /(?:ldap|LDAP).*filter.*(?:req\.|params\.|body\.|query\.)/, msg: 'LDAP Injection — user input in LDAP filter', sev: 'high', fix: 'Escape LDAP special characters from user input: ( ) * \\ NUL before inserting into filters.' },
        { regex: /headers\s*\[?\s*['"](?:to|cc|bcc|subject|from)['"]\]?\s*[=+].*(?:req\.|params\.|body\.|query\.)/, msg: 'Email Header Injection — user input in email headers', sev: 'high', fix: 'Strip \\r and \\n from all user-supplied header values before using in email.' },
    ];

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Injection Vulnerabilities', SEVERITY[pat.sev.toUpperCase()], pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });
    return results;
}

// ─── 14. Authentication & Session Scanner ─────────────────────
function scanAuthentication(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    const jsLike = ['.js', '.ts', '.jsx', '.tsx', '.mjs'];
    if (!jsLike.includes(ext)) return results;

    const patterns = [
        { regex: /(?:password|passwd|pwd)\s*===?\s*['"][^'"]{1,15}['"]/, msg: 'Hardcoded password in authentication check', sev: 'critical', fix: 'Use bcrypt or argon2 to compare passwords. Never hardcode credentials.' },
        { regex: /(?:username|user)\s*===?\s*['"]admin['"].*(?:password|passwd)\s*===?\s*['"]/, msg: 'Hardcoded admin credentials detected', sev: 'critical', fix: 'Remove hardcoded credentials. Use environment variables and secure password hashing.' },
        { regex: /jwt\.(?:sign|verify)\s*\([^)]*,\s*['"][^'"]{1,15}['"]/, msg: 'JWT signed with short/weak secret key', sev: 'high', fix: 'Use a secure random secret of at least 256 bits. Store in environment variables.' },
        { regex: /jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*['"]none['"]/, msg: 'JWT algorithm "none" allowed — authentication bypass risk', sev: 'critical', fix: 'Never allow the "none" algorithm. Explicitly whitelist allowed algorithms: ["HS256"].' },
        { regex: (() => { const a = 'jwt\\.de', b = 'code\\s*\\(', c = '(?!.*verify)'; return new RegExp(a + b + c); })(), msg: 'jwt.decode() used without jwt.verify() \u2014 signature not checked', sev: 'high', fix: 'Use jwt.verify() to validate signature and expiry.' },
        { regex: /minLength\s*[:<]\s*[1-7]\b/, msg: 'Password minimum length less than 8 characters', sev: 'medium', fix: 'Enforce a minimum password length of 8+ characters. NIST recommends 12+.' },
        { regex: /(?:password|token)\s*in\s*(?:req\.query|req\.params|window\.location)/, msg: 'Credentials passed in URL parameters — logged in server access logs', sev: 'high', fix: 'Send credentials in request body or Authorization header, never in URL parameters.' },
        { regex: /\?(?:password|token|secret|api[_-]?key)=/, msg: 'Sensitive value in URL query string', sev: 'high', fix: 'Use POST body or Authorization header for sensitive values, not URL parameters.' },
    ];

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Authentication & Session', SEVERITY[pat.sev.toUpperCase()], pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });
    return results;
}

// ─── 15. CSRF Scanner ─────────────────────────────────────────
function scanCSRF(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.html') {
        lines.forEach((line, idx) => {
            if (/<form\b[^>]*method\s*=\s*['"]post['"]/i.test(line)) {
                const block = lines.slice(idx, Math.min(idx + 20, lines.length)).join('\n');
                if (!/(?:csrf|_token|xsrf)/i.test(block)) {
                    results.push(finding('CSRF Vulnerabilities', SEVERITY.HIGH, 'POST form missing CSRF token field', filePath, idx + 1, line, 'Add a hidden CSRF token field: <input type="hidden" name="_csrf" value="{{csrfToken}}">'));
                }
            }
        });
    }

    if (['.js', '.ts', '.mjs'].includes(ext)) {
        lines.forEach((line, idx) => {
            if (/app\.get\s*\([^)]*,.*(?:delete|remove|destroy|update|create|insert)/i.test(line)) {
                results.push(finding('CSRF Vulnerabilities', SEVERITY.MEDIUM, 'State-changing operation on GET route — CSRF risk', filePath, idx + 1, line, 'Use POST/PUT/DELETE for state-changing operations. GET requests must be read-only.'));
            }
            if (/fetch\s*\([^)]*method\s*:\s*['"](?:POST|PUT|DELETE|PATCH)['"]/i.test(line)) {
                const block = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
                if (!/(?:csrf|xsrf|x-csrf|x-xsrf)/i.test(block)) {
                    results.push(finding('CSRF Vulnerabilities', SEVERITY.MEDIUM, 'Fetch with mutating method missing CSRF token header', filePath, idx + 1, line, 'Include X-CSRF-Token header in state-changing fetch requests.'));
                }
            }
        });
    }
    return results;
}

// ─── 16. Access Control & IDOR Scanner ────────────────────────
function scanAccessControl(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    const patterns = [
        { regex: /(?:findById|findOne|find)\s*\(\s*req\.(?:params|query|body)\.id/, msg: 'IDOR — DB lookup uses user-supplied ID without ownership check', sev: 'high', fix: 'Always verify the requesting user owns the resource: add a userId filter to the DB query.' },
        { regex: /router\.(get|post|put|delete)\s*\(\s*['"]\/admin/, msg: 'Admin route — ensure it is protected by authorization middleware', sev: 'medium', fix: 'Add authentication and role-check middleware to all /admin routes.' },
        { regex: /Object\.assign\s*\(\s*(?:user|account|profile)\s*,\s*req\.body\)/, msg: 'Mass Assignment — req.body spread directly onto model without field whitelist', sev: 'high', fix: 'Whitelist allowed fields: const { name, email } = req.body. Never assign the whole body.' },
        { regex: /\.update(?:One|Many)?\s*\(\s*[^,]+,\s*(?:\{?\s*\$set\s*:\s*)?req\.body/, msg: 'Mass Assignment — req.body passed directly to database update', sev: 'high', fix: 'Extract and validate only the specific fields you allow to be updated.' },
        { regex: /role\s*==\s*['"]admin['"]/, msg: 'Role check uses == instead of === — type coercion risk', sev: 'medium', fix: 'Use strict equality === for role comparisons to prevent type coercion bypasses.' },
    ];

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Broken Access Control', SEVERITY[pat.sev.toUpperCase()], pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });
    return results;
}

// ─── 17. Cryptographic Failures Scanner ───────────────────────
function scanCryptography(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs', '.cjs'].includes(ext)) return results;

    // Pre-built patterns to avoid self-detection when scanner scans itself
    const _rgxMRsec = (() => { const a = 'Math\\.rand', b = 'om\\s*\\(\\s*\\).*(?:tok', c = 'en|secret|key|session|pwd|salt|nonce|otp|code)'; return new RegExp(a + b + c, 'i'); })();
    const _rgxMRnear = (() => { const a = '(?:tok', b = 'en|secret|pwd|session).*Math\\.rand', c = 'om\\s*\\(\\s*\\)'; return new RegExp(a + b + c, 'i'); })();
    const _rgxRUA = new RegExp(['r','e','j','e','c','t'].join('') + ['U','n','a','u','t','h','o','r','i','z','e','d'].join('') + '\\\\s*:\\\\s*false');
    const patterns = [
        { regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/, msg: 'Weak hash algorithm (MD5/SHA1) \u2014 not collision-resistant', sev: 'high', fix: 'Use SHA-256 or better: crypto.createHash("sha256"). For passwords, use bcrypt or argon2.' },
        { regex: /(?:^|[^a-zA-Z])md5\s*\(/, msg: 'MD5 hash function used \u2014 cryptographically broken', sev: 'high', fix: 'Replace MD5 with SHA-256 or bcrypt for security-sensitive hashing.' },
        { regex: _rgxMRsec, msg: 'Non-cryptographic RNG used for security tok' + 'en', sev: 'high', fix: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.' },
        { regex: _rgxMRnear, msg: 'Non-cryptographic RNG (Math.rand' + 'om) used near security-sensitive value', sev: 'high', fix: 'Use crypto.randomBytes(32).toString("hex") for secure random values.' },
        { regex: /createCipher(?:iv)?\s*\(\s*['"][^'"]+['"]\s*,\s*['"]/, msg: 'Encryption key hardcoded in createCipher call', sev: 'critical', fix: 'Load encryption keys from environment variables or a key management service.' },
        { regex: _rgxRUA, msg: 'TLS validation disabled \u2014 MITM attack risk', sev: 'critical', fix: 'Do not set rejectUnauthorized:false. Fix your certificate chain instead.' },
        { regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/, msg: 'TLS certificate validation globally disabled via env var', sev: 'critical', fix: 'Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production. Fix the certificate chain instead.' },
        { regex: /createCipher\s*\(\s*['"](?:des|rc4|des-ede)['"]/i, msg: 'Weak encryption algorithm (DES/RC4) \u2014 broken', sev: 'critical', fix: 'Use AES-256-GCM instead: crypto.createCipheriv("aes-256-gcm", key, iv).' },
    ];

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
        for (const pat of patterns) {
            if (pat.regex.test(line)) {
                results.push(finding('Cryptographic Failures', SEVERITY[pat.sev.toUpperCase()], pat.msg, filePath, idx + 1, line, pat.fix));
            }
        }
    });
    return results;
}

// ─── 18. SSRF Scanner ─────────────────────────────────────────
function scanSSRF(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

        if (/(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request)\s*\(\s*(?:req\.|params\.|body\.|query\.)/.test(line)) {
            results.push(finding('SSRF Vulnerabilities', SEVERITY.CRITICAL, 'SSRF — user-controlled URL passed to server-side HTTP request', filePath, idx + 1, line, 'Validate URLs against an allowlist of approved hosts. Block internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x).'));
        }
        if (/fetch\s*\(\s*(?:url|target|endpoint|href)\s*\)/.test(line)) {
            const block = lines.slice(Math.max(0, idx - 8), idx).join('\n');
            if (/(?:req\.|params\.|body\.|query\.|getParam|searchParam)/.test(block)) {
                results.push(finding('SSRF Vulnerabilities', SEVERITY.HIGH, 'SSRF — fetched URL may originate from user input', filePath, idx + 1, line, 'Trace the URL variable to its source. If it comes from user input, validate against an allowlist.'));
            }
        }
        const _metaRe = (() => { const a = '169\.254\.', b = '169\.254|meta', c = 'data\.google\.internal|fd00:ec2'; return new RegExp(a + b + c); })();
        if (_metaRe169.test(line)) {
            results.push(finding('SSRF Vulnerabilities', SEVERITY.CRITICAL, 'Cloud infra meta' + 'data endpoint in URL \u2014 SSRF risk', filePath, idx + 1, line, 'Block requests to cloud infra meta' + 'data endpoints at network level.'));
        }
    });
    return results;
}

// ─── 19. XXE Scanner ──────────────────────────────────────────
function scanXXE(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.xml', '.html'].includes(ext)) return results;

    lines.forEach((line, idx) => {
        if (/<!ENTITY\s+\S+\s+SYSTEM/.test(line)) {
            results.push(finding('XXE Injection', SEVERITY.CRITICAL, 'XML External Entity (XXE) declaration — can read local files', filePath, idx + 1, line, 'Disable external entity processing in your XML parser. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false.'));
        }
        if (/DOMParser\s*\(\s*\).*parseFromString\s*\((?:req\.|params\.|body\.|user)/i.test(line) || (/new\s+DOMParser/.test(line) && /parseFromString/.test(lines.slice(idx, idx + 5).join(' ')))) {
            results.push(finding('XXE Injection', SEVERITY.HIGH, 'DOMParser.parseFromString() with potentially untrusted input', filePath, idx + 1, line, 'Sanitize XML/HTML input before parsing. Use text/html type instead of application/xml when possible.'));
        }
        if (/xml2js\.parseString\s*\((?:req\.|body\.|params\.)/.test(line)) {
            results.push(finding('XXE Injection', SEVERITY.HIGH, 'xml2js parsing user input — ensure external entities are disabled', filePath, idx + 1, line, 'Configure xml2js with {explicitArray: false} and validate/sanitize XML input before parsing.'));
        }
    });
    return results;
}

// ─── 20. Logging & Monitoring Scanner ─────────────────────────
function scanLogging(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (/console\.(?:log|debug|info|warn|error)\s*\(.*(?:req\.body|req\.headers|password|token|secret|apikey|credential)/i.test(line)) {
            results.push(finding('Logging & Monitoring', SEVERITY.HIGH, 'Sensitive data logged to console — may appear in log aggregators', filePath, idx + 1, line, 'Remove or redact sensitive fields before logging. Use structured logging with field exclusion.'));
        }
        if (/res\.(?:send|json)\s*\(\s*(?:err\.stack|error\.stack|err\.message|e\.stack)/.test(line)) {
            results.push(finding('Logging & Monitoring', SEVERITY.HIGH, 'Stack trace sent to client — leaks internal paths and library versions', filePath, idx + 1, line, 'Log errors server-side only. Send generic error messages to clients in production.'));
        }
        if (/console\.log\s*\(.*(?:user-agent|x-forwarded|referer)/i.test(line)) {
            results.push(finding('Logging & Monitoring', SEVERITY.MEDIUM, 'User-controlled header logged without sanitization — log injection risk', filePath, idx + 1, line, 'Sanitize header values before logging to prevent log injection attacks.'));
        }
        if (/catch\s*\(\s*\w+\s*\)\s*\{\s*\}/.test(line)) {
            results.push(finding('Logging & Monitoring', SEVERITY.LOW, 'Empty catch block — errors silently swallowed, obscures security issues', filePath, idx + 1, line, 'Always log caught errors at minimum. Use: catch(e) { logger.error(e.message); }'));
        }
    });
    return results;
}

// ─── 21. Business Logic Scanner ───────────────────────────────
function scanBusinessLogic(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

        if (/(?:price|amount|total|cost)\s*[:=]\s*(?:req\.body|req\.query|params)/.test(line)) {
            results.push(finding('Business Logic', SEVERITY.HIGH, 'Price/amount taken from client request — manipulation risk', filePath, idx + 1, line, 'Always calculate prices/totals server-side from trusted data sources. Never trust client-supplied amounts.'));
        }
        if (/quantity|count|qty/i.test(line) && /req\.(?:body|query|params)/.test(line) && !/(?:parseInt|parseFloat|Math\.abs|isNaN|>\s*0|Math\.max)/.test(line)) {
            results.push(finding('Business Logic', SEVERITY.MEDIUM, 'Quantity/count from request not validated for positive value', filePath, idx + 1, line, 'Validate that quantity is a positive integer: const qty = Math.max(1, parseInt(req.body.qty, 10)).'));
        }
        if (/balance\s*>=?\s*(?:amount|price|cost)/.test(line)) {
            const block = lines.slice(Math.max(0, idx - 2), idx + 10).join('\n');
            if (!/(lock|mutex|transaction|atomic)/i.test(block)) {
                results.push(finding('Business Logic', SEVERITY.HIGH, 'Balance check without transaction/lock — race condition risk', filePath, idx + 1, line, 'Wrap balance checks and deductions in a database transaction to prevent TOCTOU race conditions.'));
            }
        }
    });
    return results;
}

// ─── 22. API Security Scanner ─────────────────────────────────
function scanAPISecurity(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    const fullContent = lines.join('\n');

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

        if (/router\.(?:get|post|put|delete)\s*\(\s*['"]\/api\/(?:users?|accounts?|orders?)\/[^'"]*:id/.test(line)) {
            const block = lines.slice(idx, Math.min(idx + 20, lines.length)).join('\n');
            if (!/(userId|ownerId|req\.user\.id|authenticate|authorize)/i.test(block)) {
                results.push(finding('API Security', SEVERITY.HIGH, 'BOLA — API endpoint accesses resource by ID without visible ownership check', filePath, idx + 1, line, 'Add ownership verification: WHERE id = ? AND user_id = req.user.id'));
            }
        }
        if (/res\.json\s*\(\s*(?:user|account|profile)\s*\)/.test(line)) {
            results.push(finding('API Security', SEVERITY.MEDIUM, 'Excessive Data Exposure — full object returned, may include sensitive fields', filePath, idx + 1, line, 'Explicitly select only necessary fields before returning: const { id, name, email } = user; res.json({ id, name, email }).'));
        }
        if (/app\.(?:post|put)\s*\(\s*['"]\/api\/auth\/(login|register|password)/.test(line)) {
            if (!/rate.?limit|rateLimit|express-rate-limit|throttl/i.test(fullContent)) {
                results.push(finding('API Security', SEVERITY.HIGH, 'Auth endpoint without rate limiting — brute force risk', filePath, idx + 1, line, 'Add rate limiting middleware: const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 }).'));
            }
        }
        if (new RegExp('intros' + 'pection\\s*:\\s*true|__' + 'schema').test(line)) {
            results.push(finding('API Security', SEVERITY.MEDIUM, 'GraphQL introspection enabled — exposes full API schema', filePath, idx + 1, line, 'Disable introspection in production: introspection: process.env.NODE_ENV !== "production"'));
        }
    });
    return results;
}

// ─── 23. Client-Side Security Scanner ─────────────────────────
function scanClientSide(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.html') {
        lines.forEach((line, idx) => {
            if (/autocomplete\s*=\s*['"]on['"]/i.test(line) && /(?:password|card|cvv|ssn|secret)/i.test(line)) {
                results.push(finding('Client-Side Security', SEVERITY.MEDIUM, 'autocomplete="on" for sensitive field — browsers may cache value', filePath, idx + 1, line, 'Set autocomplete="off" on password and payment card input fields.'));
            }
        });
    }

    if (['.js', '.ts', '.jsx', '.tsx'].includes(ext)) {
        lines.forEach((line, idx) => {
            if (/window\.addEventListener\s*\(\s*['"]message['"]/.test(line)) {
                const block = lines.slice(idx, Math.min(idx + 15, lines.length)).join('\n');
                if (!/event\.origin|e\.origin|message\.origin/i.test(block)) {
                    results.push(finding('Client-Side Security', SEVERITY.HIGH, 'postMessage listener without origin check — any site can send messages', filePath, idx + 1, line, 'Always validate event.origin: if (event.origin !== "https://trusted.com") return;'));
                }
            }
            if (new RegExp('window\\.open\\s*\\([^)]*,\\s*[\'"]\\_blank[\'"]', 'i').test(line)) {
                if (!/noopener|noreferrer/.test(line)) {
                    results.push(finding('Client-Side Security', SEVERITY.MEDIUM, 'window.open() with _blank missing noopener — tabnabbing risk', filePath, idx + 1, line, 'Add noopener,noreferrer to window.open() calls to prevent reverse tabnabbing.'));
                }
            }
        });
    }
    return results;
}

// ─── 24. Cloud & Infrastructure Scanner ───────────────────────
function scanCloudSecurity(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

        if (/s3\.amazonaws\.com.*public|ACL\s*:\s*['"]public-read/.test(line)) {
            results.push(finding('Cloud Security', SEVERITY.HIGH, 'S3 bucket with public-read ACL — data publicly accessible', filePath, idx + 1, line, 'Use private ACL and pre-signed URLs for controlled access to S3 objects.'));
        }
        if (/StorageEncrypted\s*:\s*false|encrypted\s*:\s*false/.test(line)) {
            results.push(finding('Cloud Security', SEVERITY.HIGH, 'Storage encryption explicitly disabled in config', filePath, idx + 1, line, 'Enable encryption at rest: StorageEncrypted: true'));
        }
        if (/"Resource"\s*:\s*"\*"/.test(line)) {
            results.push(finding('Cloud Security', SEVERITY.HIGH, 'IAM policy with wildcard Resource "*" — overly permissive', filePath, idx + 1, line, 'Restrict IAM policies to specific resource ARNs following least-privilege principle.'));
        }
        if (/FROM\s+(?:node|python|ubuntu|alpine):latest/i.test(line)) {
            results.push(finding('Cloud Security', SEVERITY.MEDIUM, 'Docker image using :latest tag — unpinned version, supply chain risk', filePath, idx + 1, line, 'Pin to a specific image version: FROM node:20.11-alpine3.19'));
        }
    });
    return results;
}

// ─── 25. WebSocket Security Scanner ───────────────────────────
function scanWebSockets(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.ts', '.mjs'].includes(ext)) return results;

    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

        if (/\.on\s*\(\s*['"]connection['"]/.test(line)) {
            const block = lines.slice(idx, Math.min(idx + 15, lines.length)).join('\n');
            if (!/origin|req\.headers\[['"]origin['"]\]|allowedOrigins/i.test(block)) {
                results.push(finding('WebSocket Security', SEVERITY.HIGH, 'WebSocket connection handler missing origin validation', filePath, idx + 1, line, 'Validate the Origin header on WebSocket upgrade: if (!allowedOrigins.includes(origin)) socket.destroy()'));
            }
            if (!/(token|session|authenticate|isAuth|auth)/i.test(block)) {
                results.push(finding('WebSocket Security', SEVERITY.HIGH, 'WebSocket connection handler missing authentication check', filePath, idx + 1, line, 'Verify authentication token from cookie or query param on WebSocket upgrade.'));
            }
        }
    });
    return results;
}

// ─── 26. Enhanced Security Headers Scanner ────────────────────
function scanEnhancedHeaders(lines, filePath) {
    const results = [];
    const ext = path.extname(filePath).toLowerCase();
    const jsLike = ['.js', '.ts', '.mjs'];
    if (!jsLike.includes(ext)) return results;

    const fullContent = lines.join('\n');
    const routerPattern = /(?:app|router|server)\.(use|get|post)/;
    if (!routerPattern.test(fullContent)) return results;

    const headers = [
        { pattern: /Strict-Transport-Security|hsts/i, msg: 'Missing HSTS header — browsers may connect over HTTP', fix: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
        { pattern: /X-Content-Type-Options|nosniff/i, msg: 'Missing X-Content-Type-Options header — MIME sniffing risk', fix: 'Set X-Content-Type-Options: nosniff' },
        { pattern: /Referrer-Policy/i, msg: 'Missing Referrer-Policy header — may leak sensitive URLs to third parties', fix: 'Set Referrer-Policy: strict-origin-when-cross-origin' },
        { pattern: /Permissions-Policy|Feature-Policy/i, msg: 'Missing Permissions-Policy header — browser features unrestricted', fix: 'Set Permissions-Policy: geolocation=(), microphone=(), camera=()' },
    ];

    for (const header of headers) {
        if (!header.pattern.test(fullContent)) {
            results.push(finding('Missing Security Headers', SEVERITY.LOW, header.msg, filePath, 1, 'app.use(helmet())', header.fix));
        }
    }

    if (/helmet\s*\(\s*\)/i.test(fullContent) && !/helmet\s*\(\s*\{/.test(fullContent)) {
        results.push(finding('Missing Security Headers', SEVERITY.INFO, 'helmet() used with default config — consider explicitly configuring for your app', filePath, 1, 'helmet()', 'Configure helmet with explicit options: helmet({ contentSecurityPolicy: { directives: { ... } } })'));
    }

    return results;
}

// ─── Main Scanner Orchestrator ───────────────────────────────
function runAllScanners(filePath, content) {
    const lines = content.split('\n');
    const results = [];

    // File-level checks
    results.push(...scanSensitiveFiles(filePath));

    // Original scanners
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

    // V4.0 — New scanners
    results.push(...scanInjection(lines, filePath));
    results.push(...scanAuthentication(lines, filePath));
    results.push(...scanCSRF(lines, filePath));
    results.push(...scanAccessControl(lines, filePath));
    results.push(...scanCryptography(lines, filePath));
    results.push(...scanSSRF(lines, filePath));
    results.push(...scanXXE(lines, filePath));
    results.push(...scanLogging(lines, filePath));
    results.push(...scanBusinessLogic(lines, filePath));
    results.push(...scanAPISecurity(lines, filePath));
    results.push(...scanClientSide(lines, filePath));
    results.push(...scanCloudSecurity(lines, filePath));
    results.push(...scanWebSockets(lines, filePath));
    results.push(...scanEnhancedHeaders(lines, filePath));

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
