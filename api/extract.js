/**
 * Byse Video Extractor — Vercel Serverless Function
 * بدون بروكسي — يشتغل من أول مرة
 */

import { webcrypto as crypto } from "node:crypto";

const BLOCKS = 512, MASK = BLOCKS - 1, ROUNDS = 2;
const MUL_A = 2654435761, MUL_B = 2246822519;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

function b64u(v) { return Buffer.from(v).toString("base64url"); }
function b64uDec(v) { return Buffer.from(v, "base64url"); }
function rot(v, s) { return (v << s | v >>> 32 - s) >>> 0; }
function mul(v, f) { return Math.imul(v, f) >>> 0; }
function mix(s) {
  s[0] = s[0] + s[1] >>> 0; s[3] = rot(s[3] ^ s[0], 16);
  s[2] = s[2] + s[3] >>> 0; s[1] = rot(s[1] ^ s[2], 12);
  s[0] = s[0] + s[1] >>> 0; s[3] = rot(s[3] ^ s[0], 8);
  s[2] = s[2] + s[3] >>> 0; s[1] = rot(s[1] ^ s[2], 7);
}

function hash(bytes) {
  const state = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762]);
  for (let i = 0; i < bytes.length; i++) {
    state[0] = state[0] + bytes[i] >>> 0; state[0] = rot(state[0], 7); mix(state);
  }
  for (let i = 0; i < 8; i++) mix(state);
  const table = new Uint32Array(BLOCKS);
  for (let i = 0; i < BLOCKS; i++) { mix(state); table[i] = (state[0] ^ state[2]) >>> 0; }
  for (let r = 0; r < ROUNDS; r++) {
    for (let idx = 0; idx < BLOCKS; idx++) {
      const ti = table[idx] & MASK;
      let v = table[idx] + table[ti] >>> 0;
      v = rot(v, 13); v = (v ^ mul(table[(idx + 1) & MASK], MUL_A)) >>> 0;
      table[idx] = v; state[0] = (state[0] ^ v) >>> 0; mix(state);
    }
  }
  const out = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    mix(state); let v = state[0];
    for (let idx = 0; idx < BLOCKS / 8; idx++) {
      const tv = table[i * (BLOCKS / 8) + idx];
      v = v + tv >>> 0; v = rot(v, 5); v = (v ^ mul(tv, MUL_B)) >>> 0;
    }
    out[i] = (v ^ state[2]) >>> 0;
  }
  return out;
}

function latin1(v) {
  const o = new Uint8Array(v.length);
  for (let i = 0; i < v.length; i++) o[i] = v.charCodeAt(i) & 255;
  return o;
}

function lz(v) {
  let t = 0;
  for (let i = 0; i < v.length; i++) {
    if (v[i] === 0) { t += 32; continue; }
    return t + Math.clz32(v[i]);
  }
  return t;
}

function solvePoW(nonce, difficulty) {
  const prefix = nonce + ":";
  const pb = latin1(prefix);
  const buf = new Uint8Array(pb.length + 12);
  buf.set(pb);
  for (let c = 0; ; c++) {
    const s = String(c);
    for (let i = 0; i < s.length; i++) buf[pb.length + i] = s.charCodeAt(i);
    if (lz(hash(buf.subarray(0, pb.length + s.length))) >= difficulty) return s;
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.statusCode = 204; res.end(); return; }
  if (req.method !== "POST") { res.statusCode = 405; res.json({ success: false, error: "Use POST" }); return; }

  let body = "";
  for await (const chunk of req) body += chunk;
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { res.statusCode = 400; res.json({ success: false, error: "Invalid JSON" }); return; }

  const url = parsed?.url;
  if (!url) { res.statusCode = 400; res.json({ success: false, error: "Missing url" }); return; }

  const codeMatch = url.match(/\/e\/([a-z0-9]+)/i);
  if (!codeMatch) { res.statusCode = 400; res.json({ success: false, error: "Invalid URL" }); return; }
  const code = codeMatch[1];

  try {
    const t0 = Date.now();
    const urls = await extract(url, code);
    console.log(`✅ ${url} → ${Date.now() - t0}ms`);
    res.json({ success: true, urls, time: Date.now() - t0 });
  } catch (err) {
    console.error("❌", err.message);
    res.statusCode = 500;
    res.json({ success: false, error: err.message });
  }
}

async function extract(embedUrl, code) {
  const embedOrigin = new URL(embedUrl).origin;
  const embedHeaders = {
    "X-Embed-Origin": new URL(embedUrl).hostname,
    "X-Embed-Referer": embedUrl,
    "X-Embed-Parent": embedUrl,
  };

  // 1
  const details = await (await fetch(`${embedOrigin}/api/videos/${code}/embed/details`, {
    headers: { "User-Agent": UA, "Referer": embedUrl, ...embedHeaders }
  })).json();
  const frameBase = new URL(details.embed_frame_url || embedUrl).origin;

  // 2
  const challenge = await (await fetch(`${frameBase}/api/videos/access/challenge`, {
    method: "POST",
    headers: { "Content-Length": "0", "Origin": frameBase, "Referer": details.embed_frame_url, "User-Agent": UA }
  })).json();

  // 3
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, new TextEncoder().encode(challenge.nonce));

  // 4
  const attest = await (await fetch(`${frameBase}/api/videos/access/attest`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": frameBase, "Referer": details.embed_frame_url, "User-Agent": UA },
    body: JSON.stringify({ nonce: challenge.nonce, challenge_id: challenge.challenge_id, public_key: publicKey, signature: b64u(signature) })
  })).json();

  const cookie = `byse_viewer_id=${attest.viewer_id}; byse_device_id=${attest.device_id}`;
  const fp = { token: attest.token, viewer_id: attest.viewer_id, device_id: attest.device_id, confidence: attest.confidence };

  // 5
  const captcha = await (await fetch(`${frameBase}/api/videos/${code}/embed/captcha`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": frameBase, "Referer": details.embed_frame_url, "User-Agent": UA, "Cookie": cookie, ...embedHeaders },
    body: JSON.stringify({ fingerprint: fp })
  })).json();

  // 6
  const solution = solvePoW(captcha.pow_nonce, captcha.pow_difficulty);

  const verification = await (await fetch(`${frameBase}/api/videos/${code}/embed/captcha/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": frameBase, "Referer": details.embed_frame_url, "User-Agent": UA, "Cookie": cookie, ...embedHeaders },
    body: JSON.stringify({ pow_token: captcha.pow_token, solution, fingerprint: fp })
  })).json();

  const playbackData = await (await fetch(`${frameBase}/api/videos/${code}/embed/playback`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": frameBase, "Referer": details.embed_frame_url, "User-Agent": UA, "Cookie": cookie, "X-Captcha-Token": verification.token, ...embedHeaders },
    body: JSON.stringify({ fingerprint: fp })
  })).json();

  const playback = playbackData.playback;
  const keyBytes = Buffer.concat(playback.key_parts.filter(x => b64uDec(x).length === 16).map(b64uDec));
  const aesKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64uDec(playback.iv) }, aesKey, b64uDec(playback.payload));
  const result = JSON.parse(new TextDecoder().decode(decrypted));

  return result.sources.map(s => s.url);
}
