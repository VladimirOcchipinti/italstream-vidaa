#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const EPG_URLS = [
  'https://epgshare01.online/epgshare01/epg_ripper_IT1.xml.gz',
  'https://iptv-epg.org/files/epg-it.xml.gz'
];

const ALIASES = {
  mediaset20: ['canale20', '20mediaset', '20'],
  canale20: ['mediaset20', '20mediaset'],
  twentyseven: ['27twentyseven', 'canale27', '27'],
  '27twentyseven': ['twentyseven', 'canale27'],
  rainews24: ['rainews'],
  skytg24: ['skytg24hd', 'skytg'],
  tgcom24: ['tgcom'],
  rtl1025: ['rtl1025tv', 'rtl102'],
  radioitaliatv: ['radioitalia'],
  tv8: ['tv8italia'],
  la7d: ['la7hd'],
  nationalgeographic: ['natgeo', 'nationalgeographicchannel'],
  warnerbrosdiscovery: ['warnertv'],
  warnertv: ['warner']
};

function decodeXml(s) {
  return String(s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .trim();
}

function normKey(raw) {
  let s = String(raw || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[◉●•★☆ᴿᴬᵂ⁶⁰ᶠᵖˢ⁵⁰ᴴᴰᵁ⁴ᴷ]/g, ' ')
    .toLowerCase();
  s = s.replace(/^\s*(?:\[[^\]]*\]|\([^)]*\)|it\s*[-:|•]+|ita\s*[-:|•]+|italia\s*[-:|•]+)\s*/g, '');
  s = s.replace(/\([^)]*\)/g, ' ').replace(/\[[^\]]*\]/g, ' ');
  s = s.replace(/&/g, 'e').replace(/\+/g, 'plus');
  s = s.replace(/\b(4k|uhd|fhd|full\s*hd|hd|sd|hevc|h265|raw|50fps|60fps|multi\s*audio|linear|backup|italia|it|ita|tv|channel)\b/g, ' ');
  s = s.replace(/[^a-z0-9]/g, '');
  return s;
}

function parseXmltvDateSec(s) {
  const m = String(s || '').match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?\s*([+-]\d{4})?/);
  if (!m) return 0;
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}${m[7] ? `${m[7].slice(0, 3)}:${m[7].slice(3)}` : 'Z'}`;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
}

function parseAttrs(str) {
  const attrs = {};
  const re = /([a-zA-Z0-9_-]+)="([^"]*)"/g;
  let m;
  while ((m = re.exec(str))) attrs[m[1].toLowerCase()] = m[2];
  return attrs;
}

(async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const minSec = nowSec - 3600;
  const maxSec = nowSec + 14 * 3600;
  const channels = {};

  for (const url of EPG_URLS) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
      if (!res.ok) continue;
      const buf = Buffer.from(await res.arrayBuffer());
      const xml = (buf[0] === 0x1f && buf[1] === 0x8b) ? zlib.gunzipSync(buf).toString('utf8') : buf.toString('utf8');

      const xmlIdToKeys = new Map();
      const chRe = /<channel\s+id="([^"]+)"[^>]*>([\s\S]*?)<\/channel>/g;
      let m;
      while ((m = chRe.exec(xml))) {
        const xmlId = m[1];
        const keys = new Set();
        const k1 = normKey(xmlId.replace(/\.[a-z]{2}$/i, ''));
        if (k1) keys.add(k1);
        const dnRe = /<display-name[^>]*>([\s\S]*?)<\/display-name>/g;
        let d;
        while ((d = dnRe.exec(m[2]))) {
          const kn = normKey(decodeXml(d[1]));
          if (kn) keys.add(kn);
        }
        for (const k of [...keys]) {
          if (ALIASES[k]) ALIASES[k].forEach((a) => keys.add(a));
        }
        if (keys.size) xmlIdToKeys.set(xmlId, [...keys]);
      }

      const prByXmlId = new Map();
      const prRe = /<programme\s+([^>]*)>([\s\S]*?)<\/programme>/g;
      while ((m = prRe.exec(xml))) {
        const attrs = parseAttrs(m[1]);
        if (!xmlIdToKeys.has(attrs.channel)) continue;
        const s = parseXmltvDateSec(attrs.start);
        const e = parseXmltvDateSec(attrs.stop);
        if (!s || !e || e <= minSec || s >= maxSec) continue;
        const titleRaw = (m[2].match(/<title[^>]*>([\s\S]*?)<\/title>/) || [])[1];
        const title = decodeXml(titleRaw || '');
        if (!title || /^(no data|n\/a|nessun dato|to be announced|tba)$/i.test(title)) continue;
        const descRaw = (m[2].match(/<desc[^>]*>([\s\S]*?)<\/desc>/) || [])[1];
        const desc = decodeXml(descRaw || '').replace(/\s+/g, ' ').slice(0, 110);
        if (!prByXmlId.has(attrs.channel)) prByXmlId.set(attrs.channel, []);
        prByXmlId.get(attrs.channel).push([s, e, title, desc]);
      }

      for (const [xmlId, items] of prByXmlId.entries()) {
        items.sort((a, b) => a[0] - b[0]);
        const hasCurrent = items.some((it) => it[0] <= nowSec && it[1] > nowSec);
        for (const k of xmlIdToKeys.get(xmlId) || []) {
          if (!channels[k] || (!channels[k].some((it) => it[0] <= nowSec && it[1] > nowSec) && hasCurrent)) {
            channels[k] = items;
          }
        }
      }
    } catch (err) {
      console.error('EPG source failed:', url, err.message);
    }
  }

  const outPath = path.join(__dirname, '..', 'epg-it-compact.json');
  const payload = JSON.stringify({ updatedAt: Date.now(), channels });
  fs.writeFileSync(outPath, payload);
  console.log(`Built epg-it-compact.json: ${Object.keys(channels).length} keys, ${(payload.length / 1024).toFixed(1)} KB`);
})();
