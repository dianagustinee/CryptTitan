// ====================================
// CRYPTITAN — app.js (FIXED)
// AES-256-CBC file encryption / decryption
// ====================================

const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const port = 4000;

// ====================================
// PATHS
// ====================================
const ROOT_DIR    = __dirname;
const PUBLIC_DIR  = path.join(ROOT_DIR, 'public');
const UPLOAD_DIR  = path.join(ROOT_DIR, 'uploads');
const ENC_LOG     = path.join(ROOT_DIR, 'encryption.log');
const DEC_LOG     = path.join(ROOT_DIR, 'decryption.log');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(ENC_LOG))    fs.writeFileSync(ENC_LOG, '');
if (!fs.existsSync(DEC_LOG))    fs.writeFileSync(DEC_LOG, '');

// ====================================
// MIDDLEWARE
// ====================================
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static(ROOT_DIR, { index: 'index.html' }));
app.use('/public', express.static(PUBLIC_DIR));

// ====================================
// MULTER
// ====================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename:    (req, file, cb) => {
    const safe = path.basename(file.originalname).replace(/[/\\]/g, '_');
    cb(null, safe);
  },
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ====================================
// ROUTES
// ====================================
app.get('/', (req, res) => res.sendFile(path.join(ROOT_DIR, 'index.html')));

const sha256Key = (pass) => crypto.createHash('sha256').update(String(pass), 'utf8').digest();
const safeUnlink = (p) => { try { if (p && fs.existsSync(p)) fs.unlinkSync(p); } catch (_) {} };
const appendLog = (logPath, filename) => fs.appendFileSync(logPath, filename + '\n', 'utf8');

// ---------- ENKRIPSI ----------
app.post('/encrypt', upload.single('file'), (req, res) => {
  const uploaded = req.file ? req.file.path : null;
  try {
    if (!req.file) return res.status(400).send('File tidak ada.');
    if (!req.body || !req.body.key || !String(req.body.key).trim()) {
      safeUnlink(uploaded);
      return res.status(400).send('Kunci (password) tidak boleh kosong.');
    }

    const key = sha256Key(req.body.key);
    const iv  = crypto.randomBytes(16);
    const data      = fs.readFileSync(uploaded);
    const cipher    = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([iv, cipher.update(data), cipher.final()]);

    const originalName = path.basename(req.file.originalname);
    const outputPath   = path.join(UPLOAD_DIR, 'encrypted_' + originalName);

    fs.writeFileSync(outputPath, encrypted);
    appendLog(ENC_LOG, originalName);
    safeUnlink(uploaded);

    return res.json({ filename: originalName });
  } catch (error) {
    console.error('[ENCRYPT ERROR]', error);
    safeUnlink(uploaded);
    return res.status(500).send('Enkripsi gagal: ' + error.message);
  }
});

// ---------- DEKRIPSI ----------
app.post('/decrypt', upload.single('file'), (req, res) => {
  const uploaded = req.file ? req.file.path : null;
  try {
    if (!req.file) return res.status(400).send('File tidak ada.');
    if (!req.body || !req.body.key || !String(req.body.key).trim()) {
      safeUnlink(uploaded);
      return res.status(400).send('Kunci (password) tidak boleh kosong.');
    }

    const originalName = path.basename(req.file.originalname);
    if (!originalName.startsWith('encrypted_')) {
      safeUnlink(uploaded);
      return res.status(400).send('File ini bukan hasil enkripsi. Upload file berawalan "encrypted_".');
    }

    const key  = sha256Key(req.body.key);
    const data = fs.readFileSync(uploaded);
    if (data.length < 17) {
      safeUnlink(uploaded);
      return res.status(400).send('File terenkripsi rusak / terlalu pendek.');
    }

    const iv       = data.subarray(0, 16);
    const content  = data.subarray(16);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(content), decipher.final()]);

    const baseName   = originalName.replace(/^encrypted_/, '');
    const outputPath = path.join(UPLOAD_DIR, 'decrypted_' + baseName);

    fs.writeFileSync(outputPath, decrypted);
    appendLog(DEC_LOG, baseName);
    safeUnlink(uploaded);

    return res.json({ filename: baseName });
  } catch (error) {
    console.error('[DECRYPT ERROR]', error);
    safeUnlink(uploaded);
    return res.status(400).send('Dekripsi gagal: pastikan file & kunci benar. Detail: ' + error.message);
  }
});

// ---------- LOGS ----------
function readLogFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/).map(l => l.trim()).filter(Boolean)
    .map(filename => ({ filename }));
}
app.get('/logs/encrypted', (req, res) => res.json(readLogFile(ENC_LOG)));
app.get('/logs/decrypted', (req, res) => res.json(readLogFile(DEC_LOG)));

// ---------- DOWNLOAD ----------
app.get('/download/:type/:filename', (req, res) => {
  const { type } = req.params;
  const filename = path.basename(req.params.filename);
  if (!['encrypted', 'decrypted'].includes(type)) return res.status(400).send('Tipe tidak valid.');
  const filePath = path.join(UPLOAD_DIR, `${type}_${filename}`);
  if (!fs.existsSync(filePath)) return res.status(404).send('File tidak ditemukan.');
  return res.download(filePath, `${type}_${filename}`);
});

// ---------- ERROR HANDLER ----------
app.use((err, req, res, next) => {
  console.error('[UNHANDLED]', err);
  if (err instanceof multer.MulterError) return res.status(400).send('Upload error: ' + err.message);
  return res.status(500).send('Server error: ' + err.message);
});

app.listen(port, () => console.log(`Server berjalan pada http://localhost:${port}`));