// ==========================================================
// CRYPTITAN — app.js  (CLIENT-SIDE / GitHub Pages compatible)
// ----------------------------------------------------------
// 100% berjalan di browser. Tidak ada fetch/POST ke server.
// Gunakan Web Crypto API (AES-256-CBC, key = SHA-256(password)).
//
// Format file terenkripsi:
//   [ IV 16 byte ] [ ciphertext AES-256-CBC ]
//
// Nama file:
//   Encrypt : <namaAsli>           -> encrypted_<namaAsli>
//   Decrypt : encrypted_<namaAsli> -> decrypted_<namaAsli>
//   Compress: <nama>.<ext>         -> <nama>_compressed.<ext>   (GZIP bytes,
//                                     ekstensi asli dipertahankan sesuai
//                                     permintaan user)
//
// Script ini AGRESIF meng-intercept:
//   - semua <form> (submit di-cancel & diproses lokal)
//   - tombol #encryptBtn/#decryptBtn/#cmpForm/#cmpBtn/[data-action=...]
//   - fungsi global runEncryption()/runDecryption()/runCompress()
//   - fetch()/XMLHttpRequest ke /encrypt /decrypt /compress
//     -> dicegat & dijalankan lokal, supaya HTML lama yang masih
//        pakai fetch POST tidak menyebabkan status "Uploading &
//        encrypting..." macet.
// ==========================================================

(function () {
  'use strict';

  // ---------------- UI helpers ----------------
  function statusEls() {
    return document.querySelectorAll(
      '#status, .status, #statusDisplay, #stat, [data-status], ' +
      '#console-log, #consoleLog, .console-log, #log, #output'
    );
  }
  function setStatus(msg, type) {
    statusEls().forEach((el) => {
      if (el.tagName === 'PRE' || el.classList.contains('console-log') ||
          el.id === 'console-log' || el.id === 'consoleLog' ||
          el.id === 'log' || el.id === 'output') {
        el.textContent += '\n> ' + msg;
        el.scrollTop = el.scrollHeight;
      } else {
        el.textContent = msg;
      }
      if (type === 'error') el.style.color = '#ff6b6b';
      if (type === 'ok')    el.style.color = '#7CFC7C';
    });
    if (type === 'error') console.error('[CrypTitan]', msg);
    else console.log('[CrypTitan]', msg);
  }

  function triggerDownload(bytes, filename, mime) {
    return new Promise((resolve) => {
      const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.rel = 'noopener';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // beri jeda supaya browser sempat memicu unduhan
      setTimeout(() => { URL.revokeObjectURL(url); resolve(); }, 300);
    });
  }

  // ---------------- Web Crypto helpers ----------------
  async function deriveKey(password) {
    const pw   = new TextEncoder().encode(String(password));
    const hash = await crypto.subtle.digest('SHA-256', pw);
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

  // baca File pakai FileReader (sesuai permintaan user)
  function readFileAsBytes(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload  = () => resolve(new Uint8Array(fr.result));
      fr.onerror = () => reject(new Error('Gagal membaca file.'));
      fr.readAsArrayBuffer(file);
    });
  }

  // ---------------- log persist (localStorage) ----------------
  function appendLog(kind, filename) {
    try {
      const key  = kind === 'encrypt' ? 'cryptitan_enc_log'
                 : kind === 'decrypt' ? 'cryptitan_dec_log'
                 :                      'cryptitan_cmp_log';
      const list = JSON.parse(localStorage.getItem(key) || '[]');
      list.push({ filename, at: new Date().toISOString() });
      localStorage.setItem(key, JSON.stringify(list));
    } catch (_) {}
  }

  // ---------------- inti aksi ----------------
  async function runEncrypt(file, password) {
    if (!file)     throw new Error('Pilih file terlebih dahulu.');
    if (!password) throw new Error('Kunci (password) tidak boleh kosong.');

    setStatus('Uploading & encrypting ' + file.name + ' ...');
    const bytes     = await readFileAsBytes(file);
    const encrypted = await encryptBytes(bytes, password);
    const outName   = 'encrypted_' + file.name;

    await triggerDownload(encrypted, outName, 'application/octet-stream');
    appendLog('encrypt', file.name);
    setStatus('Encryption Success! File diunduh sebagai ' + outName, 'ok');
  }

  async function runDecrypt(file, password) {
    if (!file)     throw new Error('Pilih file terlebih dahulu.');
    if (!password) throw new Error('Kunci (password) tidak boleh kosong.');
    if (!file.name.startsWith('encrypted_')) {
      throw new Error('File ini bukan hasil enkripsi. Nama harus diawali "encrypted_".');
    }

    setStatus('Uploading & decrypting ' + file.name + ' ...');
    const bytes = await readFileAsBytes(file);
    let decrypted;
    try {
      decrypted = await decryptBytes(bytes, password);
    } catch (e) {
      throw new Error('Dekripsi gagal: kunci salah atau file rusak.');
    }
    const baseName = file.name.replace(/^encrypted_/, '');
    const outName  = 'decrypted_' + baseName;

    await triggerDownload(decrypted, outName, 'application/octet-stream');
    appendLog('decrypt', baseName);
    setStatus('Decryption Success! File diunduh sebagai ' + outName, 'ok');
  }

  async function runCompress(file) {
    if (!file) throw new Error('Pilih file terlebih dahulu.');
    setStatus('Compressing ' + file.name + ' ...');

    // pakai CompressionStream (native), fallback: kirim apa adanya
    let outBytes;
    if (typeof CompressionStream !== 'undefined') {
      const cs     = new CompressionStream('gzip');
      const stream = file.stream().pipeThrough(cs);
      const buf    = await new Response(stream).arrayBuffer();
      outBytes     = new Uint8Array(buf);
    } else {
      outBytes = await readFileAsBytes(file);
    }

    // Pertahankan ekstensi asli (permintaan user: "png ya png, jpeg ya jpeg").
    const dot   = file.name.lastIndexOf('.');
    const base  = dot > 0 ? file.name.slice(0, dot) : file.name;
    const ext   = dot > 0 ? file.name.slice(dot)    : '';
    const outName = base + '_compressed' + ext;

    await triggerDownload(outBytes, outName, file.type || 'application/octet-stream');
    appendLog('compress', file.name);
    const ratio = Math.max(0, Math.round((1 - outBytes.length / file.size) * 100));
    setStatus('Compression Success! ' + file.name + ' → ' + outName +
              ' (hemat ' + ratio + '%).', 'ok');
  }

  // ---------------- pencari input di sekitar form/tombol ----------------
  function findFileInput(scope) {
    return (scope && scope.querySelector && scope.querySelector('input[type="file"]'))
        || document.querySelector('input[type="file"]');
  }
  function findKeyInput(scope) {
    const sel = 'input[name="key"], input[name="password"], input[name="passphrase"], ' +
                '#key, #password, #keyInput, #passphrase, ' +
                'input[type="password"], input[type="text"]';
    return (scope && scope.querySelector && scope.querySelector(sel))
        || document.querySelector(sel);
  }

  async function handleAction(kind, scope) {
    const fileEl = findFileInput(scope);
    const keyEl  = kind === 'compress' ? null : findKeyInput(scope);
    const file   = fileEl && fileEl.files && fileEl.files[0];
    const pass   = keyEl && keyEl.value;

    try {
      if (kind === 'encrypt')       await runEncrypt(file, pass);
      else if (kind === 'decrypt')  await runDecrypt(file, pass);
      else                          await runCompress(file);
    } catch (err) {
      setStatus((err && err.message) || String(err), 'error');
      try { alert(err.message || String(err)); } catch (_) {}
    }
  }

  // ---------------- pasang listener ----------------
  function detectKindFromAction(action) {
    action = (action || '').toLowerCase();
    if (action.includes('encrypt'))  return 'encrypt';
    if (action.includes('decrypt'))  return 'decrypt';
    if (action.includes('compress') || action.includes('kompres')) return 'compress';
    return null;
  }

  function bind() {
    // 1) Semua <form> — tangkap di fase capture supaya script inline lama
    //    (yang mungkin melakukan fetch POST) tidak sempat berjalan.
    document.querySelectorAll('form').forEach((form) => {
      const kind = detectKindFromAction(form.getAttribute('action'))
                || detectKindFromAction(form.id);
      if (!kind) return;
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();
        handleAction(kind, form);
      }, true);
    });

    // 2) Tombol umum
    document.querySelectorAll(
      '#encryptBtn, #btnEncrypt, [data-action="encrypt"]'
    ).forEach((b) => b.addEventListener('click', (e) => {
      e.preventDefault(); e.stopImmediatePropagation(); handleAction('encrypt');
    }, true));

    document.querySelectorAll(
      '#decryptBtn, #btnDecrypt, [data-action="decrypt"]'
    ).forEach((b) => b.addEventListener('click', (e) => {
      e.preventDefault(); e.stopImmediatePropagation(); handleAction('decrypt');
    }, true));

    document.querySelectorAll(
      '#compressBtn, #cmpBtn, [data-action="compress"]'
    ).forEach((b) => b.addEventListener('click', (e) => {
      e.preventDefault(); e.stopImmediatePropagation(); handleAction('compress');
    }, true));

    // 3) Global (jika HTML lama memanggil onclick="runEncryption()")
    window.runEncryption = () => handleAction('encrypt');
    window.runDecryption = () => handleAction('decrypt');
    window.runCompress   = () => handleAction('compress');
    window.runEncrypt    = () => handleAction('encrypt');
    window.runDecrypt    = () => handleAction('decrypt');
  }

  // ---------------- cegat fetch/XHR ke endpoint lama ----------------
  // Supaya kode HTML lama yang masih memanggil fetch('/encrypt', ...)
  // tidak menggantung di status "Uploading & encrypting...".
  (function patchNetwork() {
    const origFetch = window.fetch ? window.fetch.bind(window) : null;
    window.fetch = async function (input, init) {
      try {
        const url    = typeof input === 'string' ? input : (input && input.url) || '';
        const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        const kind   = detectKindFromAction(url);
        if (kind && method === 'POST') {
          // ambil FormData dari body kalau ada
          let fd = init && init.body;
          if (fd instanceof FormData) {
            const file = fd.get('file') || fd.get('upload') || fd.get('data');
            const pass = fd.get('key')  || fd.get('password') || fd.get('passphrase') || '';
            if (kind === 'compress') await runCompress(file);
            else if (kind === 'encrypt') await runEncrypt(file, pass);
            else await runDecrypt(file, pass);
            return new Response('{"ok":true,"clientSide":true}', {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }
      } catch (err) {
        setStatus(err.message || String(err), 'error');
        return new Response('{"ok":false}', { status: 500 });
      }
      if (!origFetch) throw new Error('fetch tidak tersedia');
      return origFetch(input, init);
    };

    // XHR shim minimal
    const OrigXHR = window.XMLHttpRequest;
    if (OrigXHR) {
      function ShimXHR() {
        const xhr = new OrigXHR();
        let _url = '', _method = 'GET';
        const origOpen = xhr.open;
        const origSend = xhr.send;
        xhr.open = function (m, u) { _method = m; _url = u; return origOpen.apply(xhr, arguments); };
        xhr.send = function (body) {
          const kind = detectKindFromAction(_url);
          if (kind && String(_method).toUpperCase() === 'POST' && body instanceof FormData) {
            const file = body.get('file') || body.get('upload') || body.get('data');
            const pass = body.get('key')  || body.get('password') || body.get('passphrase') || '';
            const run  = kind === 'compress' ? runCompress(file)
                       : kind === 'encrypt'  ? runEncrypt(file, pass)
                       :                       runDecrypt(file, pass);
            run.then(() => {
              Object.defineProperty(xhr, 'readyState', { value: 4, configurable: true });
              Object.defineProperty(xhr, 'status',     { value: 200, configurable: true });
              Object.defineProperty(xhr, 'responseText', { value: '{"ok":true}', configurable: true });
              xhr.onreadystatechange && xhr.onreadystatechange();
              xhr.onload && xhr.onload();
            }).catch((err) => {
              setStatus(err.message || String(err), 'error');
              xhr.onerror && xhr.onerror(err);
            });
            return; // JANGAN kirim beneran
          }
          return origSend.apply(xhr, arguments);
        };
        return xhr;
      }
      window.XMLHttpRequest = ShimXHR;
    }
  })();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }

  setStatus('CrypTitan siap (mode client-side, AES-256-CBC / Web Crypto API).', 'ok');
})();
