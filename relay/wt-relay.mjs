// wt-relay.mjs — THROWAWAY WebTransport (HTTP/3) relay for the cross-device LNA/serverCertificateHashes spike.
// NOT production. Runs on the Windows relay laptop (real test) or Mac (dev). Self-generates a short-lived
// ECDSA self-signed cert on first run (no openssl / no key transfer). Serves WebTransport over QUIC/TLS; the
// browser pins the cert by SHA-256 via serverCertificateHashes. Per-stream pinned-identity signed-challenge +
// AES-GCM channel (same crypto as the earlier PoC). Synthetic only. Logs every session/stream for evidence.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { Http3Server, quicheLoaded } from '@fails-components/webtransport';
import { readFileSync, writeFileSync } from 'fs';
import cryptoNode from 'crypto';
const { subtle } = globalThis.crypto || cryptoNode.webcrypto;
const wc = globalThis.crypto?.subtle ? globalThis.crypto : cryptoNode.webcrypto;
x509.cryptoProvider.set(wc);
const SITE = process.env.SITE || 'siteA', RELAY = process.env.RELAY || 'relay-001', PORT = +(process.env.PORT || 4433);
const certPath = new URL('./cert.pem', import.meta.url), keyPath = new URL('./key.pem', import.meta.url);
const b64 = b => Buffer.from(b).toString('base64'), ub = s => Uint8Array.from(Buffer.from(s, 'base64'));
const pubId = j => j.x + '.' + j.y;
const gS = () => subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const gD = () => subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const ex = k => subtle.exportKey('jwk', k);
const iV = j => subtle.importKey('jwk', j, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const iS = j => subtle.importKey('jwk', j, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const iDp = j => subtle.importKey('jwk', j, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const iDpub = j => subtle.importKey('jwk', j, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
const sign = async (pj, s) => b64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await iS(pj), Buffer.from(s)));
const verify = async (pj, s, sig) => subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await iV(pj), ub(sig), Buffer.from(s));
const sk = async (privj, pubj) => { const bits = await subtle.deriveBits({ name: 'ECDH', public: await iDpub(pubj) }, await iDp(privj), 256); const h = await subtle.digest('SHA-256', bits); return subtle.importKey('raw', h, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); };
const enc = async (k, s) => { const iv = cryptoNode.randomBytes(12); const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, Buffer.from(s)); return { iv: b64(iv), ct: b64(new Uint8Array(ct)) }; };
const dec = async (k, iv, ct) => Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv: ub(iv) }, k, ub(ct))).toString();

async function ensureCert() {
  try { return { cert: readFileSync(certPath, 'utf8'), key: readFileSync(keyPath, 'utf8') }; } catch (e) { }
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const keys = await wc.subtle.generateKey(alg, true, ['sign', 'verify']);
  const crt = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=cs-wt-relay', notBefore: new Date(Date.now() - 60000), notAfter: new Date(Date.now() + 13 * 864e5), keys, signingAlgorithm: alg });
  const cert = crt.toString('pem'), key = x509.PemConverter.encode(await wc.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY');
  writeFileSync(certPath, cert); writeFileSync(keyPath, key);
  return { cert, key };
}

// long-term app-identity key (persisted for restart test)
let ltPriv, ltPub;
try { const j = JSON.parse(readFileSync(new URL('./lt.json', import.meta.url), 'utf8')); ltPriv = j.priv; ltPub = j.pub; }
catch (e) { const lt = await gS(); ltPriv = await ex(lt.privateKey); ltPub = await ex(lt.publicKey); writeFileSync(new URL('./lt.json', import.meta.url), JSON.stringify({ priv: ltPriv, pub: ltPub })); }
let devices = {}; const seen = new Set(), sessions = {};
try { devices = JSON.parse(readFileSync(new URL('./devices.json', import.meta.url), 'utf8')); } catch (e) {}
const saveDevices = () => { try { writeFileSync(new URL('./devices.json', import.meta.url), JSON.stringify(devices)); } catch (e) {} };

async function handle(q) {
  switch (q.op) {
    case 'relay-pub': return { ok: true, siteId: SITE, relayId: RELAY, pub: ltPub };
    case 'enroll': if (!q.deviceId || !q.devicePub) return { ok: false, code: 'bad' }; devices[q.deviceId] = q.devicePub; saveDevices(); return { ok: true, enrolled: q.deviceId };
    case 'connect': {
      if (q.siteId !== SITE) return { ok: false, code: 'wrong-site' };
      if (q.relayId !== RELAY) return { ok: false, code: 'wrong-relay' };
      if (!devices[q.deviceId]) return { ok: false, code: 'rogue-device' };
      if (Math.abs(Date.now() - q.ts) > 60000) return { ok: false, code: 'stale-ts' };
      if (seen.has(q.clientNonce)) return { ok: false, code: 'replay' };
      if (!await verify(devices[q.deviceId], [q.clientNonce, q.ts, q.siteId, q.relayId, q.deviceId, pubId(q.clientEphPub)].join('|'), q.sig)) return { ok: false, code: 'bad-client-sig' };
      seen.add(q.clientNonce);
      const eph = await gD(), rEphPub = await ex(eph.publicKey), rEphPriv = await ex(eph.privateKey), relayNonce = b64(cryptoNode.randomBytes(16));
      const rsig = await sign(ltPriv, [q.clientNonce, relayNonce, SITE, RELAY, pubId(rEphPub), pubId(q.clientEphPub)].join('|'));
      const key = await sk(rEphPriv, q.clientEphPub), sid = b64(cryptoNode.createHash('sha256').update(q.clientNonce + relayNonce).digest()).slice(0, 24);
      sessions[sid] = { key };
      return { ok: true, sessionId: sid, relayNonce, relayEphPub: rEphPub, siteId: SITE, relayId: RELAY, sig: rsig };
    }
    case 'data': { const s = sessions[q.sessionId]; if (!s) return { ok: false, code: 'no-session' }; let p; try { p = await dec(s.key, q.iv, q.ct); } catch (e) { return { ok: false, code: 'auth-fail-tamper' }; } return { ok: true, ...(await enc(s.key, JSON.stringify({ echo: JSON.parse(p), relayId: RELAY, ts: Date.now() }))) }; }
    default: return { ok: false, code: 'unknown-op' };
  }
}
async function readAll(readable) { const r = readable.getReader(); const chunks = []; for (;;) { const { value, done } = await r.read(); if (done) break; chunks.push(Buffer.from(value)); } return Buffer.concat(chunks); }

await quicheLoaded;
const { cert, key } = await ensureCert();
const der = new cryptoNode.X509Certificate(cert).raw;
const CERT_SHA256 = cryptoNode.createHash('sha256').update(der).digest('hex');
const server = new Http3Server({ port: PORT, host: '0.0.0.0', secret: 'cs-wt-spike', cert, privKey: key });
server.startServer();
const T = () => new Date().toISOString().slice(11, 19);
console.log('============================================================');
console.log(`cs-wt-relay  WebTransport/HTTP-3  udp/${PORT}  site=${SITE} relay=${RELAY}`);
console.log(`CERT_SHA256 = ${CERT_SHA256}`);
console.log(`RELAY_LONGTERM_PUB_B64 = ${b64(Buffer.from(JSON.stringify(ltPub)))}`);
console.log(`enrolled devices: ${Object.keys(devices).length}`);
console.log('Paste CERT_SHA256 into the browser shell "Pinned cert SHA-256" field.');
console.log('============================================================');
let N = 0;
(async () => {
  const reader = server.sessionStream('/wt').getReader();
  for (;;) {
    const { value: session, done } = await reader.read(); if (done) break;
    const id = ++N;
    (async () => {
      try {
        await session.ready;
        console.log(`[${T()}] session #${id} ESTABLISHED (browser QUIC/WebTransport session arrived at this machine)`);
        const br = session.incomingBidirectionalStreams.getReader();
        for (;;) {
          const { value: st, done } = await br.read(); if (done) break;
          (async () => {
            try {
              const q = JSON.parse((await readAll(st.readable)).toString() || '{}');
              const resp = await handle(q);
              console.log(`[${T()}] session #${id} op=${q.op || '?'}${q.deviceId ? ' device=' + q.deviceId : ''} -> ${resp.ok ? 'ok' : 'REJECT:' + resp.code}`);
              const w = st.writable.getWriter(); await w.write(Buffer.from(JSON.stringify(resp))); await w.close();
            } catch (e) { }
          })();
        }
        console.log(`[${T()}] session #${id} closed`);
      } catch (e) { }
    })();
  }
})();
