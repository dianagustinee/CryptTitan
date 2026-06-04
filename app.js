// ====================================
// IMPORT MODULE
// ====================================

//framework untuk membangun web ini
const express = require('express');
//untuk mengelola pengunggahan file pada server
const multer = require('multer');
//library Node.js kriptografi yang berguna untuk mengamankan dan melindungi data
const crypto = require('crypto');
//untuk membaca, menulis, menghapus, memindahkan, dan mengelola berkas dan direktori pada sistem file.
const fs = require('fs');
//untuk mengelola jalur (path) file dan direktori 
const path = require('path');
//instance
const app = express();
//protokol untuk menjalankan http
const port = 4000;

// ====================================
// MIDDLEWARE
// ====================================

// Mengizinkan Express untuk membaca data dari form (req.body)
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true}));


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// static file (CSS, img, html di folder public)
app.use(express.static(path.join(__dirname, 'public')));

// pastikan folder & file penting ada
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('encryption.log')) fs.writeFileSync('encryption.log', '');
if (!fs.existsSync('decryption.log')) fs.writeFileSync('decryption.log', '');

// ===================================
// MULTER (UPLOAD)
// ===================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// ===================================
// ROUTES
// ===================================

// Menampilkan halaman index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===================================
// ENKRIPSI
// ===================================

// Endpoint untuk mengenkripsi file
app.post('/encrypt', upload.single('file'), (req, res) => {
  try {
    if (!req.file || !req.body.key) {
      return res.status(400).send('File atau kunci tidak ada');
    }

    const key = crypto.createHash('sha256').update(req.body.key).digest();
    const iv = crypto.randomBytes(16);

    const data = fs.readFileSync(req.file.path);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([iv, cipher.update(data), cipher.final()]);

    const outputPath = `uploads/encrypted_${req.file.originalname}`;
    fs.writeFileSync(outputPath, encrypted);

    fs.appendFileSync('encryption.log', `${req.file.originalname}\n`);
    fs.unlinkSync(req.file.path);

    res.json({ filename: req.file.originalname });
  } catch (error) {
    console.error(error);
    res.status(500).send(`Enkripsi gagal: ${error.message}`);
  }
});

// ===================================
// DESKRIPSI
// ===================================

// Endpoint untuk mendekripsi file
app.post('/decrypt', upload.single('file'), (req, res) => {
  try {
    if (!req.file || !req.body.key) {
      return res.status(400).send('File atau kunci tidak ada');
    }

    if (!req.file.originalname.startsWith('encrypted_')) {
      return res.status(400).send('File ini bukan hasil enkripsi. Silakan upload file hasil enkripsi (nama diawali encrypted_) lalu masukkan kunci yang sama.');
    }

    const key = crypto.createHash('sha256').update(req.body.key).digest();
    const data = fs.readFileSync(req.file.path);

    const iv = data.slice(0, 16);
    const content = data.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(content), decipher.final()]);

    const outputPath = `uploads/decrypted_${req.file.originalname}`;
    fs.writeFileSync(outputPath, decrypted);

    fs.appendFileSync('decryption.log', `${req.file.originalname}\n`);
    fs.unlinkSync(req.file.path);

    res.json({ filename: req.file.originalname });
  } catch (error) {
    console.error(error);
    res.status(400).send(`Dekripsi gagal: pastikan file hasil enkripsi (encrypted_) dan kunci benar. Detail: ${error.message}`);
  }
});

// ===================================
// LOGS
// ===================================

function readLogFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, 'utf8');
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((filename) => ({ filename }));
}

app.get('/logs/encrypted', (req, res) => {
  res.json(readLogFile('encryption.log'));
});

app.get('/logs/decrypted', (req, res) => {
  res.json(readLogFile('decryption.log'));
});

// ===================================
// DOWNLOAD
// ===================================

app.get('/download/:type/:filename', (req, res) => {
  const { type, filename } = req.params;
  const filePath = path.join(__dirname, 'uploads', `${type}_${filename}`);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File tidak ditemukan');
  }

  res.download(filePath);
});

// ===================================
// SERVER
// ===================================

// Menjalankan server
app.listen(port, () => {
  console.log(`Server berjalan pada http://localhost:${port}`);
});