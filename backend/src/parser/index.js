/**
 * parser.js
 * Splits raw log content into structured lines for analysis.
 */

function parseLines(content) {
  if (!content || typeof content !== "string") return [];

  return content
    .split(/\r?\n/)
    .map((text, index) => ({
      lineNumber: index + 1,
      text: text.trim(),
    }))
    .filter((line) => line.text.length > 0);
}

module.exports = { parseLines };
