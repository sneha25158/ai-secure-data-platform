/**
 * server.js
 * Express entry point — defines POST /analyze endpoint.
 */

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const { analyzeContent } = require('./src/controller');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use(express.static(__dirname));

// ── File Upload (multer) ────────────────────────────────────────────────────
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${file.originalname}`;
    cb(null, unique);
  },
});

const fileFilter = (req, file, cb) => {
  const allowed = ['.log', '.txt'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only .log and .txt files are supported.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

// ── Routes ──────────────────────────────────────────────────────────────────

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'AI Secure Data Intelligence Platform' });
});

/**
 * POST /analyze
 * Accepts:
 *   - multipart/form-data with field `file` (.log / .txt)
 *   - multipart/form-data with field `text` (raw log text)
 *   - application/json with body { text: "..." }
 */
app.post('/analyze', upload.single('file'), (req, res) => {
  try {
    let rawContent = '';

    if (req.file) {
      // File upload path
      const filePath = req.file.path;
      rawContent = fs.readFileSync(filePath, 'utf-8');

      // Clean up temp file after reading
      fs.unlink(filePath, () => {});
    } else if (req.body && req.body.text) {
      // Text input path
      rawContent = req.body.text;
    } else {
      return res.status(400).json({
        error:
          "No input provided. Send a file (field: 'file') or text (field: 'text').",
      });
    }

    const result = analyzeContent(rawContent);
    return res.status(200).json(result);
  } catch (err) {
    console.error('Analysis error:', err.message);
    return res.status(500).json({
      error: 'Internal server error during analysis.',
      detail: err.message,
    });
  }
});

// Multer error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  AI Secure Data Intelligence Platform`);
  console.log(`   Backend running at: http://localhost:${PORT}`);
  console.log(`   Frontend served at: http://localhost:${PORT}\n`);
});
