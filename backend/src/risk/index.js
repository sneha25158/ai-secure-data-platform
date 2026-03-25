/**
 * riskEngine.js
 * Calculates risk score, risk level, and generates template-based insights.
 */

const RISK_WEIGHTS = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 2,
};

const LEVEL_THRESHOLDS = {
  high: 40,
  medium: 15,
  low: 0,
};

/**
 * Deduplicate findings by type — keep all occurrences for scoring
 * but track unique types for insights.
 */
function calculateRiskScore(findings) {
  return findings.reduce((score, finding) => {
    return score + (RISK_WEIGHTS[finding.risk] || 0);
  }, 0);
}

function getRiskLevel(score) {
  if (score >= LEVEL_THRESHOLDS.high) return "high";
  if (score >= LEVEL_THRESHOLDS.medium) return "medium";
  return "low";
}

/**
 * Generate human-readable insights based on finding types.
 */
function generateInsights(findings) {
  const insights = [];
  const types = new Set(findings.map((f) => f.type));

  if (types.has("password") || types.has("hardcoded_credentials")) {
    insights.push("⚠️ Sensitive credentials are exposed in plain text within logs.");
  }

  if (types.has("api_key")) {
    insights.push("🔑 API keys detected in logs — rotate them immediately to prevent unauthorized access.");
  }

  if (types.has("token")) {
    insights.push("🪙 Authentication tokens found in logs — these can be used to impersonate users.");
  }

  if (types.has("repeated_login_failure")) {
    const entry = findings.find((f) => f.type === "repeated_login_failure");
    insights.push(
      `🚨 Multiple failed login attempts detected (${entry?.count || "3+"} occurrences) — possible brute-force attack.`
    );
  }

  if (types.has("stack_trace")) {
    insights.push("📛 Error stack traces reveal internal system structure — suppress in production environments.");
  }

  if (types.has("email")) {
    insights.push("📧 Email addresses found in logs — review data retention and privacy compliance.");
  }

  if (types.has("phone_number")) {
    insights.push("📞 Phone numbers detected in logs — ensure PII handling complies with data protection rules.");
  }

  if (insights.length === 0) {
    insights.push("✅ No significant security issues detected in this log sample.");
  }

  return insights;
}

/**
 * Generate a human-readable summary sentence.
 */
function generateSummary(findings, riskLevel) {
  const count = findings.length;
  if (count === 0) return "No security issues detected in the provided log data.";

  const criticalCount = findings.filter((f) => f.risk === "critical").length;
  const highCount = findings.filter((f) => f.risk === "high").length;

  let summary = `Detected ${count} security finding${count !== 1 ? "s" : ""} in log data`;

  if (criticalCount > 0) {
    summary += ` including ${criticalCount} critical issue${criticalCount !== 1 ? "s" : ""}`;
  }
  if (highCount > 0) {
    summary += `${criticalCount > 0 ? " and" : " including"} ${highCount} high-severity issue${
      highCount !== 1 ? "s" : ""
    }`;
  }

  summary += `. Overall risk level: ${riskLevel.toUpperCase()}.`;
  return summary;
}

function analyze(findings) {
  const riskScore = calculateRiskScore(findings);
  const riskLevel = getRiskLevel(riskScore);
  const insights = generateInsights(findings);
  const summary = generateSummary(findings, riskLevel);

  return { riskScore, riskLevel, insights, summary };
}

module.exports = { analyze };
