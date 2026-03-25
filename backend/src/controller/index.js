/**
 * controller.js
 * Orchestrates the full analysis pipeline:
 * parse → detect → risk → format response
 */

const { parseLines } = require("../parser");
const { detect } = require("../detector");
const { analyze } = require("../risk");

function analyzeContent(rawContent) {
  // Step 1: Parse raw text into structured lines
  const lines = parseLines(rawContent);

  if (lines.length === 0) {
    return {
      summary: "No log content provided or content was empty.",
      content_type: "logs",
      findings: [],
      risk_score: 0,
      risk_level: "low",
      action: "masked",
      insights: ["No data to analyze."],
    };
  }

  // Step 2: Run detection across all lines
  const findings = detect(lines);

  // Step 3: Compute risk score, level, and insights
  const { riskScore, riskLevel, insights, summary } = analyze(findings);

  // Step 4: Format response
  return {
    summary,
    content_type: "logs",
    findings: findings.map(({ type, risk, line, count }) => ({
      type,
      risk,
      line,
      ...(count !== undefined && { occurrences: count }),
    })),
    risk_score: riskScore,
    risk_level: riskLevel,
    action: "masked",
    insights,
  };
}

module.exports = { analyzeContent };
