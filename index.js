#!/usr/bin/env node

/**
 * Security Review Agent — CLI Entry Point
 * Scans a web app directory for security vulnerabilities
 * and generates a beautiful HTML report.
 *
 * Usage:
 *   node index.js <path-to-scan>
 *   node index.js ../my-app
 *   node index.js .
 */

const fs = require('fs');
const path = require('path');
const { runAllScanners, calculateScore, getScoreGrade, SEVERITY } = require('./scanners');
const { generateReport } = require('./report');

// ─── Config ──────────────────────────────────────────────────
const SCAN_EXTENSIONS = new Set(['.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.css', '.json', '.env']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.vercel', '.cache', 'coverage', '__pycache__', 'vendor']);
const MAX_FILE_SIZE = 1024 * 1024; // 1MB — skip huge files

// ─── Colors for terminal ─────────────────────────────────────
const c = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m',
};

// ─── File Discovery ──────────────────────────────────────────
function discoverFiles(dir) {
    const files = [];

    function walk(currentDir) {
        let entries;
        try {
            entries = fs.readdirSync(currentDir, { withFileTypes: true });
        } catch (err) {
            return; // Skip unreadable directories
        }

        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);

            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                    walk(fullPath);
                }
                continue;
            }

            if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                const basename = entry.name.toLowerCase();

                // Check for env files specifically (they have no extension sometimes)
                if (basename.startsWith('.env') || SCAN_EXTENSIONS.has(ext)) {
                    try {
                        const stat = fs.statSync(fullPath);
                        if (stat.size <= MAX_FILE_SIZE) {
                            files.push(fullPath);
                        }
                    } catch (err) {
                        // Skip
                    }
                }
            }
        }
    }

    walk(dir);
    return files;
}

// ─── Main ────────────────────────────────────────────────────
function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        console.log(`
${c.bold}${c.magenta}🛡️  Security Review Agent${c.reset}
${c.dim}Static security analysis for web apps${c.reset}

${c.bold}Usage:${c.reset}
  node index.js <path-to-scan> [options]

${c.bold}Examples:${c.reset}
  node index.js ../my-app
  node index.js .
  node index.js ~/projects/my-website --output report.html

${c.bold}Options:${c.reset}
  --output, -o <file>   Output file path (default: security-report.html)
  --help, -h            Show this help
`);
        process.exit(0);
    }

    // Parse arguments
    let targetDir = args[0];
    let outputFile = 'security-report.html';

    const outputIdx = args.indexOf('--output');
    const outputIdxShort = args.indexOf('-o');
    if (outputIdx !== -1 && args[outputIdx + 1]) {
        outputFile = args[outputIdx + 1];
    } else if (outputIdxShort !== -1 && args[outputIdxShort + 1]) {
        outputFile = args[outputIdxShort + 1];
    }

    // Resolve paths
    targetDir = path.resolve(targetDir);

    if (!fs.existsSync(targetDir)) {
        console.error(`${c.red}✗ Directory not found: ${targetDir}${c.reset}`);
        process.exit(1);
    }

    if (!fs.statSync(targetDir).isDirectory()) {
        console.error(`${c.red}✗ Not a directory: ${targetDir}${c.reset}`);
        process.exit(1);
    }

    // Header
    console.log('');
    console.log(`${c.bold}${c.magenta}  🛡️  Security Review Agent${c.reset}`);
    console.log(`${c.dim}  ─────────────────────────────────${c.reset}`);
    console.log(`  ${c.cyan}Target:${c.reset} ${targetDir}`);
    console.log('');

    // Discover files
    const startTime = Date.now();
    const files = discoverFiles(targetDir);

    if (files.length === 0) {
        console.log(`${c.yellow}  ⚠ No scannable files found in ${targetDir}${c.reset}`);
        process.exit(0);
    }

    console.log(`  ${c.blue}📁 Found ${files.length} files to scan${c.reset}`);

    // Scan
    const allFindings = [];
    let scannedCount = 0;

    for (const filePath of files) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const relativePath = path.relative(targetDir, filePath);
            const findings = runAllScanners(relativePath, content);
            allFindings.push(...findings);
            scannedCount++;
        } catch (err) {
            // Skip unreadable files
        }
    }

    const scanDuration = Date.now() - startTime;

    // Calculate score
    const score = calculateScore(allFindings);
    const gradeInfo = getScoreGrade(score);

    // Summary counts
    const counts = {
        [SEVERITY.CRITICAL]: 0,
        [SEVERITY.HIGH]: 0,
        [SEVERITY.MEDIUM]: 0,
        [SEVERITY.LOW]: 0,
        [SEVERITY.INFO]: 0,
    };
    for (const f of allFindings) counts[f.severity]++;

    // Terminal output
    console.log(`  ${c.green}✓ Scanned ${scannedCount} files in ${scanDuration}ms${c.reset}`);
    console.log('');

    // Score display
    const scoreColor = score >= 75 ? c.green : score >= 50 ? c.yellow : c.red;
    console.log(`  ${c.bold}Security Score: ${scoreColor}${score}/100 (${gradeInfo.grade})${c.reset}`);
    console.log('');

    // Severity breakdown
    if (counts[SEVERITY.CRITICAL] > 0) {
        console.log(`  ${c.bgRed}${c.white} CRITICAL ${c.reset} ${counts[SEVERITY.CRITICAL]} findings`);
    }
    if (counts[SEVERITY.HIGH] > 0) {
        console.log(`  ${c.red}  HIGH     ${c.reset} ${counts[SEVERITY.HIGH]} findings`);
    }
    if (counts[SEVERITY.MEDIUM] > 0) {
        console.log(`  ${c.yellow}  MEDIUM   ${c.reset} ${counts[SEVERITY.MEDIUM]} findings`);
    }
    if (counts[SEVERITY.LOW] > 0) {
        console.log(`  ${c.blue}  LOW      ${c.reset} ${counts[SEVERITY.LOW]} findings`);
    }
    if (counts[SEVERITY.INFO] > 0) {
        console.log(`  ${c.dim}  INFO     ${c.reset} ${counts[SEVERITY.INFO]} findings`);
    }

    if (allFindings.length === 0) {
        console.log(`  ${c.green}${c.bold}✅ No security issues found!${c.reset}`);
    }

    console.log('');

    // Generate report
    const displayDir = path.basename(targetDir);
    const reportHTML = generateReport(allFindings, scannedCount, displayDir, score, gradeInfo, scanDuration, targetDir);

    // Write report
    const outputPath = path.resolve(outputFile);
    fs.writeFileSync(outputPath, reportHTML, 'utf-8');

    console.log(`  ${c.green}${c.bold}📄 Report saved: ${c.reset}${c.cyan}${outputPath}${c.reset}`);
    console.log(`  ${c.dim}Open in browser to view the full report${c.reset}`);
    console.log('');
}

main();
