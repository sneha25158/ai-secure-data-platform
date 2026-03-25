/**
 * detector.js
 * Detects sensitive data and security issues in log lines using regex patterns.
 */

const PATTERNS = {
  // Sensitive Data
  email: {
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    risk: "low",
    type: "email",
  },
  phone: {
    regex: /(\+?\d[\d\s\-().]{7,}\d)/g,
    risk: "low",
    type: "phone_number",
  },
  password: {
    regex: /password\s*[=:]\s*\S+/gi,
    risk: "critical",
    type: "password",
  },
  api_key: {
    regex: /(api[_\-]?key\s*[=:]\s*\S+|sk-[a-zA-Z0-9]{20,})/gi,
    risk: "high",
    type: "api_key",
  },
  token: {
    regex: /(token\s*[=:]\s*\S+|bearer\s+[a-zA-Z0-9\-._~+/]+=*)/gi,
    risk: "high",
    type: "token",
  },

  // Security Issues
  hardcoded_credentials: {
    regex: /(secret\s*[=:]\s*\S+|credentials?\s*[=:]\s*\S+|auth\s*[=:]\s*\S+)/gi,
    risk: "critical",
    type: "hardcoded_credentials",
  },
  stack_trace: {
    regex: /\b(Exception|Error|Traceback|StackTrace|at\s+[\w.]+\([\w.:]+\))/g,
    risk: "medium",
    type: "stack_trace",
  },
};

const LOGIN_FAILED_REGEX = /login\s*(failed|failure|unsuccessful|invalid)/gi;

/**
 * Scan a single line for all patterns.
 * Returns array of findings for that line.
 */
function scanLine(lineText, lineNumber) {
  const findings = [];

  for (const [key, { regex, risk, type }] of Object.entries(PATTERNS)) {
    const cloned = new RegExp(regex.source, regex.flags);
    if (cloned.test(lineText)) {
      findings.push({ type, risk, line: lineNumber });
    }
  }

  return findings;
}

/**
 * Count login failure occurrences across all lines.
 */
function countLoginFailures(lines) {
  let count = 0;
  const lineNumbers = [];

  for (const { text, lineNumber } of lines) {
    LOGIN_FAILED_REGEX.lastIndex = 0;
    if (LOGIN_FAILED_REGEX.test(text)) {
      count++;
      lineNumbers.push(lineNumber);
    }
  }

  return { count, lineNumbers };
}

/**
 * Run full detection on parsed lines.
 * Returns all findings including repeated login failure detection.
 */
function detect(lines) {
  const findings = [];

  for (const { text, lineNumber } of lines) {
    const lineFindings = scanLine(text, lineNumber);
    findings.push(...lineFindings);
  }

  // Check for repeated login failures (>= 3 triggers suspicious flag)
  const { count, lineNumbers } = countLoginFailures(lines);
  if (count >= 3) {
    findings.push({
      type: "repeated_login_failure",
      risk: "medium",
      line: lineNumbers[lineNumbers.length - 1],
      count,
    });
  }

  return findings;
}

module.exports = { detect };
