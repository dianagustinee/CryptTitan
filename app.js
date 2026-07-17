// ==========================================================
// CRYPTITAN — app.js  (CLIENT-SIDE / GitHub Pages compatible)
// ----------------------------------------------------------
// Tidak perlu server. Semua enkripsi & dekripsi berjalan di
// browser memakai Web Crypto API (native, tanpa CDN).
//
// Format file terenkripsi (kompatibel dgn versi Node lama):
//   [ IV 16 byte ] [ ciphertext AES-256-CBC ]
//   key = SHA-256(password)
//
// Nama file:
//   Enkripsi : <namaAsli>          →  encrypted_<namaAsli>
//   Dekripsi : encrypted_<namaAsli> →  decrypted_<namaAsli>
//
// Cara kerja:
//   Script ini otomatis menangkap SEMUA <form> yang action-nya
//   mengandung "/encrypt" atau "/decrypt" (submit via fetch POST
//   di HTML lama tidak lagi jalan di GitHub Pages → 405).
//   Selain itu juga mendukung tombol dgn id umum:
//     #encryptBtn / #decryptBtn / [data-action="encrypt"|"decrypt"]
// ==========================================================

(function () {
  'use strict';

  // ---------- util UI ----------
  function log(msg, type) {
    const box = document.querySelector('#console-log, #consoleLog, .console-log, #log, #output');
    if (box) {
      const line = document.createElement('div');
      line.textContent = '> ' + msg;
      if (type === 'error') line.style.color = '#ff6b6b';
      if (type === 'ok')    line.style.color = '#7CFC7C';
      box.appendChild(line);
      box.scrollTop = box.scrollHeight;
    }
    if (type === 'error') console.error('[CrypTitan]', msg);
    else console.log('[CrypTitan]', msg);
  }

  function triggerDownload(bytes, filename, mime) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  // ---------- crypto helpers (Web Crypto API) ----------
  async function deriveKey(password) {
    const pwBytes = new TextEncoder().encode(String(password));
    const hash    = await crypto.subtle.digest('SHA-256', pwBytes); // 32 byte
    return crypto.subtle.importKey('raw', hash, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  }

  async function encryptBytes(plainBytes, password) {
    const key = await deriveKey(password);
    const iv  = crypto.getRandomValues(new Uint8Array(16));
    const ct  = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, plainBytes)
    );
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0);
    out.set(ct, iv.length);
    return out;
  }

  async function decryptBytes(encBytes, password) {
    if (encBytes.length < 17) throw new Error('File terenkripsi rusak / terlalu pendek.');
    const key = await deriveKey(password);
    const iv  = encBytes.slice(0, 16);
    const ct  = encBytes.slice(16);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
    return new Uint8Array(pt);
  }

  function readFileAsBytes(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload  = () => resolve(new Uint8Array(fr.result));
      fr.onerror = () => reject(new Error('Gagal membaca file.'));
      fr.readAsArrayBuffer(file);
    });
  }

  // ---------- log persist (localStorage, gantikan encryption.log/decryption.log) ----------
  function appendLog(kind, filename) {
    try {
      const key  = kind === 'encrypt' ? 'cryptitan_enc_log' : 'cryptitan_dec_log';
      const list = JSON.parse(localStorage.getItem(key) || '[]');
      list.push({ filename, at: new Date().toISOString() });
      localStorage.setItem(key, JSON.stringify(list));
    } catch (_) { /* ignore */ }
  }

  // ---------- inti aksi ----------
  async function runEncrypt(file, password) {
    if (!file)     throw new Error('Pilih file terlebih dahulu.');
    if (!password) throw new Error('Kunci (password) tidak boleh kosong.');

    log('Mengenkripsi ' + file.name + ' ...');
    const bytes     = await readFileAsBytes(file);
    const encrypted = await encryptBytes(bytes, password);
    const outName   = 'encrypted_' + file.name;

    triggerDownload(encrypted, outName, 'application/octet-stream');
    appendLog('encrypt', file.name);
    log('Selesai. File diunduh sebagai ' + outName, 'ok');
  }

  async function runDecrypt(file, password) {
    if (!file)     throw new Error('Pilih file terlebih dahulu.');
    if (!password) throw new Error('Kunci (password) tidak boleh kosong.');
    if (!file.name.startsWith('encrypted_')) {
      throw new Error('File ini bukan hasil enkripsi. Nama harus diawali "encrypted_".');
    }

    log('Mendekripsi ' + file.name + ' ...');
    const bytes = await readFileAsBytes(file);
    let decrypted;
    try {
      decrypted = await decryptBytes(bytes, password);
    } catch (e) {
      throw new Error('Dekripsi gagal: kunci salah atau file rusak.');
    }
    const baseName = file.name.replace(/^encrypted_/, '');
    const outName  = 'decrypted_' + baseName;

    triggerDownload(decrypted, outName, 'application/octet-stream');
    appendLog('decrypt', baseName);
    log('Selesai. File diunduh sebagai ' + outName, 'ok');
  }

  // ---------- pencari input di sekitar tombol/form ----------
  function findFileInput(scope) {
    return (scope && scope.querySelector && scope.querySelector('input[type="file"]'))
        || document.querySelector('input[type="file"]');
  }
  function findKeyInput(scope) {
    const sel = 'input[name="key"], input[name="password"], #key, #password, #keyInput, input[type="password"], input[type="text"]';
    return (scope && scope.querySelector && scope.querySelector(sel))
        || document.querySelector(sel);
  }

  async function handleAction(kind, scope) {
    const fileEl = findFileInput(scope);
    const keyEl  = findKeyInput(scope);
    const file   = fileEl && fileEl.files && fileEl.files[0];
    const pass   = keyEl && keyEl.value;

    try {
      if (kind === 'encrypt') await runEncrypt(file, pass);
      else                    await runDecrypt(file, pass);
    } catch (err) {
      log(err.message || String(err), 'error');
      alert(err.message || String(err));
    }
  }

  // ---------- pasang listener ----------
  function bind() {
    // 1) Tangkap SEMUA form yang action-nya /encrypt atau /decrypt
    document.querySelectorAll('form').forEach((form) => {
      const action = (form.getAttribute('action') || '').toLowerCase();
      let kind = null;
      if (action.includes('/encrypt') || action.endsWith('encrypt')) kind = 'encrypt';
      if (action.includes('/decrypt') || action.endsWith('decrypt')) kind = 'decrypt';
      if (!kind) return;
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        handleAction(kind, form);
      });
    });

    // 2) Tombol dgn id umum
    const enc = document.querySelector('#encryptBtn, #btnEncrypt, [data-action="encrypt"]');
    if (enc) enc.addEventListener('click', (e) => { e.preventDefault(); handleAction('encrypt'); });

    const dec = document.querySelector('#decryptBtn, #btnDecrypt, [data-action="decrypt"]');
    if (dec) dec.addEventListener('click', (e) => { e.preventDefault(); handleAction('decrypt'); });

    // 3) Expose global (dipanggil dari onclick="runEncryption()" dsb.)
    window.runEncryption = () => handleAction('encrypt');
    window.runDecryption = () => handleAction('decrypt');
    window.runEncrypt    = () => handleAction('encrypt');
    window.runDecrypt    = () => handleAction('decrypt');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }

  log('CrypTitan siap (mode client-side, AES-256-CBC / Web Crypto API).', 'ok');
})();
