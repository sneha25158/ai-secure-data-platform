function detect(lines) {
  const findings = [];

  lines.forEach((lineObj) => {
    const text = lineObj.text.toLowerCase();
    const lineNumber = lineObj.lineNumber;

    if (text.includes('email')) {
      findings.push({ type: 'email', risk: 'low', line: lineNumber });
    }

    if (text.includes('password')) {
      findings.push({ type: 'password', risk: 'critical', line: lineNumber });
    }

    if (text.includes('api_key')) {
      findings.push({ type: 'api_key', risk: 'high', line: lineNumber });
    }

    if (text.includes('error') || text.includes('stack')) {
      findings.push({ type: 'stack_trace', risk: 'medium', line: lineNumber });
    }
  });

  return findings;
}

module.exports = { detect };
