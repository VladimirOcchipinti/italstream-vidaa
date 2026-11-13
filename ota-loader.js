/* ==========================================================================
   ItalStream+ VO — Encrypted OTA Auto-Updater Bootloader (ES5 / Smart TV Safe)
   Compatibile con: Samsung Tizen, Amazon Firestick, Android TV, Hisense VIDAA
   Tutti i pacchetti remoti sono cifrati ChaCha20 (256-bit) + MAC Tag a 64-bit.
   ========================================================================== */
(function () {
  'use strict';

  var EMBEDDED_WEB_BUILD = 223;
  var GIST_ID = 'cac1232f3e1c83cf3dd412639a2e3770';
  var GIST_OWNER = 'VladimirOcchipinti';
  var STORAGE_KEY = 'italstream_ota_web_v1';
  var REMOTE_CFG_KEY = 'italstream_ota_remote_cfg_v1';

  var OTA_KEY_WORDS = [
    0x9f4b2c71, 0x38e1a6d5, 0x72c059be, 0xd4186f33,
    0x5a9e318c, 0xc704b269, 0x1e87d54a, 0x83f260b7
  ];

  var imul32 = Math.imul || function (a, b) {
    var ah = (a >>> 16) & 0xffff;
    var al = a & 0xffff;
    var bh = (b >>> 16) & 0xffff;
    var bl = b & 0xffff;
    return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0)) >>> 0;
  };

  function rotl32(v, c) {
    return ((v << c) | (v >>> (32 - c))) >>> 0;
  }

  function quarterRound(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
  }

  function chacha20Block(keyWords, counter, nonceWords, outBytes) {
    var st = new Uint32Array(16);
    var wk = new Uint32Array(16);
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    var i;
    for (i = 0; i < 8; i++) st[4 + i] = keyWords[i] >>> 0;
    st[12] = counter >>> 0;
    st[13] = nonceWords[0] >>> 0;
    st[14] = nonceWords[1] >>> 0;
    st[15] = nonceWords[2] >>> 0;
    for (i = 0; i < 16; i++) wk[i] = st[i];

    for (var r = 0; r < 10; r++) {
      quarterRound(wk, 0, 4, 8, 12);
      quarterRound(wk, 1, 5, 9, 13);
      quarterRound(wk, 2, 6, 10, 14);
      quarterRound(wk, 3, 7, 11, 15);
      quarterRound(wk, 0, 5, 10, 15);
      quarterRound(wk, 1, 6, 11, 12);
      quarterRound(wk, 2, 7, 8, 13);
      quarterRound(wk, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
      var w = (wk[i] + st[i]) >>> 0;
      var o = i * 4;
      outBytes[o] = w & 0xff;
      outBytes[o + 1] = (w >>> 8) & 0xff;
      outBytes[o + 2] = (w >>> 16) & 0xff;
      outBytes[o + 3] = (w >>> 24) & 0xff;
    }
  }

  function readU32LE(buf, off) {
    return ((buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)) + (buf[off + 3] * 0x1000000)) >>> 0;
  }

  function computeTag8(block0, cipherBytes, cipherOffset, cipherLen) {
    var h1 = (readU32LE(block0, 0) ^ 0x811c9dc5) >>> 0;
    var h2 = (readU32LE(block0, 4) ^ 0xc9dc5118) >>> 0;
    var k1 = (readU32LE(block0, 8) | 1) >>> 0;
    var k2 = (readU32LE(block0, 12) | 1) >>> 0;

    for (var i = 0; i < cipherLen; i++) {
      var b = cipherBytes[cipherOffset + i];
      h1 = imul32(h1 ^ b, 0x01000193) >>> 0;
      h2 = imul32(h2 ^ ((b + (i & 0xff)) & 0xff), 0x85ebca6b) >>> 0;
      if ((i & 63) === 63) {
        h1 = (rotl32((h1 + k1) >>> 0, 13) ^ h2) >>> 0;
        h2 = (rotl32((h2 + k2) >>> 0, 17) ^ h1) >>> 0;
      }
    }
    h1 = imul32(h1 ^ cipherLen, k1) >>> 0;
    h2 = imul32(h2 ^ cipherLen, k2) >>> 0;
    h1 = (h1 ^ readU32LE(block0, 16)) >>> 0;
    h2 = (h2 ^ readU32LE(block0, 20)) >>> 0;

    var tag = new Uint8Array(8);
    tag[0] = h1 & 0xff; tag[1] = (h1 >>> 8) & 0xff; tag[2] = (h1 >>> 16) & 0xff; tag[3] = (h1 >>> 24) & 0xff;
    tag[4] = h2 & 0xff; tag[5] = (h2 >>> 8) & 0xff; tag[6] = (h2 >>> 16) & 0xff; tag[7] = (h2 >>> 24) & 0xff;
    return tag;
  }

  function base64ToBytes(b64) {
    var clean = String(b64 || '').replace(/[\r\n\s]/g, '');
    var bin = atob(clean);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i) & 0xff;
    }
    return out;
  }

  function utf8Decode(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8').decode(bytes);
    }
    var out = '';
    var i = 0;
    while (i < bytes.length) {
      var c = bytes[i++];
      if (c < 128) {
        out += String.fromCharCode(c);
      } else if (c > 191 && c < 224) {
        out += String.fromCharCode(((c & 31) << 6) | (bytes[i++] & 63));
      } else if (c > 239 && c < 365) {
        var u = (((c & 7) << 18) | ((bytes[i++] & 63) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63)) - 0x10000;
        out += String.fromCharCode(0xd800 + (u >> 10), 0xdc00 + (u & 1023));
      } else {
        out += String.fromCharCode(((c & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63));
      }
    }
    return out;
  }

  function decryptBase64ToString(b64Str) {
    var packet = base64ToBytes(b64Str);
    if (packet.length < 24 || packet[0] !== 0x56 || packet[1] !== 0x4f || packet[2] !== 0x45 || packet[3] !== 0x31) {
      throw new Error('Header OTA non valido');
    }
    var nonceWords = [
      readU32LE(packet, 4),
      readU32LE(packet, 8),
      readU32LE(packet, 12)
    ];
    var block0 = new Uint8Array(64);
    chacha20Block(OTA_KEY_WORDS, 0, nonceWords, block0);

    var cipherLen = packet.length - 24;
    var expectedTag = computeTag8(block0, packet, 24, cipherLen);
    var diff = 0;
    for (var t = 0; t < 8; t++) diff |= (packet[16 + t] ^ expectedTag[t]);
    if (diff !== 0) {
      throw new Error('Integrita pacchetto OTA fallita');
    }

    var out = new Uint8Array(cipherLen);
    var block = new Uint8Array(64);
    var counter = 1;
    var pos = 0;
    while (pos < cipherLen) {
      chacha20Block(OTA_KEY_WORDS, counter++, nonceWords, block);
      var take = Math.min(64, cipherLen - pos);
      for (var k = 0; k < take; k++) {
        out[pos + k] = packet[24 + pos + k] ^ block[k];
      }
      pos += take;
    }
    return utf8Decode(out);
  }

  function fetchWithTimeout(url, ms) {
    return new Promise(function (resolve, reject) {
      var done = false;
      var xhr = new XMLHttpRequest();
      var timer = setTimeout(function () {
        if (!done) {
          done = true;
          try { xhr.abort(); } catch (e) {}
          reject(new Error('timeout'));
        }
      }, ms);
      try {
        xhr.open('GET', url, true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4 || done) return;
          done = true;
          clearTimeout(timer);
          if (xhr.status >= 200 && xhr.status < 300 && xhr.responseText) {
            resolve(xhr.responseText);
          } else {
            reject(new Error('HTTP ' + xhr.status));
          }
        };
        xhr.onerror = function () {
          if (!done) {
            done = true;
            clearTimeout(timer);
            reject(new Error('network'));
          }
        };
        xhr.send();
      } catch (err) {
        if (!done) {
          done = true;
          clearTimeout(timer);
          reject(err);
        }
      }
    });
  }

  function showOtaToast(msg) {
    try {
      var div = document.createElement('div');
      div.style.cssText = 'position:fixed;bottom:36px;right:36px;z-index:99999;background:rgba(16,185,129,0.95);color:#042f2e;font-weight:800;font-size:20px;padding:14px 24px;border-radius:14px;box-shadow:0 12px 32px rgba(0,0,0,0.6);transition:opacity 0.4s ease;';
      div.textContent = msg;
      document.body.appendChild(div);
      setTimeout(function () { div.style.opacity = '0'; }, 4200);
      setTimeout(function () { if (div.parentNode) div.parentNode.removeChild(div); }, 4700);
    } catch (e) {}
  }

  function loadBuiltinScripts() {
    var s1 = document.createElement('script');
    s1.src = 'standalone-engine.js';
    s1.onload = function () {
      var s2 = document.createElement('script');
      s2.src = 'app.js';
      document.body.appendChild(s2);
    };
    s1.onerror = function () {
      var s2 = document.createElement('script');
      s2.src = 'app.js';
      document.body.appendChild(s2);
    };
    document.body.appendChild(s1);
  }

  function bootFromDecryptedBundle(bundleObj, showBanner) {
    try {
      if (bundleObj.css) {
        var styleEl = document.createElement('style');
        styleEl.id = 'italstream-ota-css';
        styleEl.textContent = bundleObj.css;
        document.head.appendChild(styleEl);
      }
      var engEl = document.createElement('script');
      engEl.text = bundleObj.engineJs;
      document.body.appendChild(engEl);

      if (!window.ItalStreamStandalone) {
        throw new Error('Standalone engine missing after OTA eval');
      }

      var appEl = document.createElement('script');
      appEl.text = bundleObj.appJs;
      document.body.appendChild(appEl);

      window.__ITALSTREAM_OTA_ACTIVE_VERSION = bundleObj.version || ('build-' + bundleObj.build);
      if (showBanner) {
        showOtaToast('✨ ItalStream+ aggiornato in automatico (v' + (bundleObj.version || bundleObj.build) + ')');
      }
      return true;
    } catch (err) {
      try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
      loadBuiltinScripts();
      return false;
    }
  }

  function applyRemoteConfigIfPresent(manifest) {
    if (!manifest || !manifest.remoteConfig) return;
    try {
      localStorage.setItem(REMOTE_CFG_KEY, JSON.stringify(manifest.remoteConfig));
      var extraSources = manifest.remoteConfig.extraIptvSources;
      if (Array.isArray(extraSources) && extraSources.length > 0) {
        var raw = localStorage.getItem('italstream_iptv_sources_v1');
        var list = raw ? JSON.parse(raw) : [];
        if (!Array.isArray(list)) list = [];
        var changed = false;
        for (var i = 0; i < extraSources.length; i++) {
          var es = extraSources[i];
          if (!es || !es.id) continue;
          var exists = false;
          for (var j = 0; j < list.length; j++) {
            if (list[j] && list[j].id === es.id) { exists = true; break; }
          }
          if (!exists) {
            list.push(es);
            changed = true;
          }
        }
        if (changed) localStorage.setItem('italstream_iptv_sources_v1', JSON.stringify(list));
      }
    } catch (e) {}
  }

  function fetchLatestManifestAndUrls(timeoutMs) {
    var rawM = 'https://gist.githubusercontent.com/' + GIST_OWNER + '/' + GIST_ID + '/raw/m.dat?t=' + Math.floor(Date.now() / 30000);
    return fetchWithTimeout(rawM, timeoutMs)
      .then(function (mB64) {
        var manifest = JSON.parse(decryptBase64ToString(mB64));
        return {
          manifest: manifest,
          wUrl: 'https://gist.githubusercontent.com/' + GIST_OWNER + '/' + GIST_ID + '/raw/w.dat?t=' + Date.now(),
          aUrl: 'https://gist.githubusercontent.com/' + GIST_OWNER + '/' + GIST_ID + '/raw/a.dat?t=' + Date.now()
        };
      })
      .catch(function () {
        var apiUrl = 'https://api.github.com/gists/' + GIST_ID + '?t=' + Math.floor(Date.now() / 30000);
        return fetchWithTimeout(apiUrl, timeoutMs + 2500).then(function (jsonTxt) {
          var g = JSON.parse(jsonTxt);
          var files = (g && g.files) || {};
          var mFile = files['m.dat'];
          if (!mFile) throw new Error('No m.dat');
          var wRawUrl = files['w.dat'] && files['w.dat'].raw_url;
          var aRawUrl = files['a.dat'] && files['a.dat'].raw_url;
          var pPromise = (mFile.content && !mFile.truncated)
            ? Promise.resolve(mFile.content)
            : fetchWithTimeout(mFile.raw_url, timeoutMs + 1500);
          return pPromise.then(function (mB64) {
            var manifest = JSON.parse(decryptBase64ToString(mB64));
            return {
              manifest: manifest,
              wUrl: wRawUrl || ('https://gist.githubusercontent.com/' + GIST_OWNER + '/' + GIST_ID + '/raw/w.dat?t=' + Date.now()),
              aUrl: aRawUrl || ('https://gist.githubusercontent.com/' + GIST_OWNER + '/' + GIST_ID + '/raw/a.dat?t=' + Date.now())
            };
          });
        });
      });
  }

  function startBootSequence() {
    // Se servito dal server locale Mac (http://127.0.0.1:4321 o LAN), carica direttamente i file freschi del server
    if (/^https?:/i.test(window.location.protocol) && window.location.port === '4321') {
      loadBuiltinScripts();
      return;
    }

    var cachedRecord = null;
    var activeBuild = EMBEDDED_WEB_BUILD;
    try {
      var rawStored = localStorage.getItem(STORAGE_KEY);
      if (rawStored) {
        var parsed = JSON.parse(rawStored);
        if (parsed && Number(parsed.build) > EMBEDDED_WEB_BUILD && parsed.b64) {
          cachedRecord = parsed;
          activeBuild = Number(parsed.build);
        }
      }
    } catch (e) {}

    fetchLatestManifestAndUrls(3500)
      .then(function (res) {
        var manifest = res.manifest || {};
        applyRemoteConfigIfPresent(manifest);

        // Notifica Android TV / Firestick se esiste anche un nuovo guscio APK nativo
        try {
          if (window.ItalStreamAndroid && window.ItalStreamAndroid.checkNativeApkOta && manifest.androidBuild) {
            window.ItalStreamAndroid.checkNativeApkOta(Number(manifest.androidBuild), res.aUrl, String(manifest.version || ''));
          }
        } catch (e) {}

        var remoteWebBuild = Number(manifest.webBuild || manifest.build || 0);
        if (remoteWebBuild > activeBuild) {
          return fetchWithTimeout(res.wUrl, 12000).then(function (wB64) {
            var bundleObj = JSON.parse(decryptBase64ToString(wB64));
            try {
              localStorage.setItem(STORAGE_KEY, JSON.stringify({
                build: remoteWebBuild,
                version: manifest.version || bundleObj.version || String(remoteWebBuild),
                b64: wB64
              }));
            } catch (e) {}
            bootFromDecryptedBundle(bundleObj, true);
          });
        }

        if (cachedRecord) {
          var cachedObj = JSON.parse(decryptBase64ToString(cachedRecord.b64));
          bootFromDecryptedBundle(cachedObj, false);
        } else {
          loadBuiltinScripts();
        }
      })
      .catch(function () {
        if (cachedRecord) {
          try {
            var cachedObj = JSON.parse(decryptBase64ToString(cachedRecord.b64));
            bootFromDecryptedBundle(cachedObj, false);
            return;
          } catch (e) {}
        }
        loadBuiltinScripts();
      });
  }

  window.ItalStreamOtaCrypto = {
    decryptBase64ToString: decryptBase64ToString,
    EMBEDDED_WEB_BUILD: EMBEDDED_WEB_BUILD
  };

  startBootSequence();
})();
