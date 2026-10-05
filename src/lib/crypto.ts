/**
 * Bridge Pro v32 — client-side message encryption.
 *
 * SECURITY NOTE (read before production):
 * - Uses ONLY standard primitives from the browser WebCrypto API
 *   (ECDH P-256, HKDF-SHA-256, AES-256-GCM). No home-grown algorithms.
 * - The *protocol* composition below (static-static ECDH per device + per-message
 *   content key wrapped for each recipient device) is NOT independently audited
 *   and has no forward secrecy or post-compromise security. Production must
 *   replace it with an audited protocol implementation (e.g. libsignal / MLS
 *   via a reviewed library) and pass an external cryptographic review.
 * - Private keys are generated as NON-EXTRACTABLE CryptoKeys and kept in
 *   IndexedDB on this device. They are never sent to the server.
 * - For these reasons the UI never labels this path as "verified E2EE".
 */

export const MESSAGE_ALG = "ECDH-P256+HKDF-SHA256+AES-256-GCM" as const;

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
export const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export interface DeviceKeyPair {
  privateKey: CryptoKey;
  publicKeyB64: string;
  fingerprint: string;
}

export async function generateDeviceKeyPair(): Promise<DeviceKeyPair> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64: b64(spki), fingerprint: await fingerprintOf(b64(spki)) };
}

/** Human-comparable fingerprint (SHA-256 of SPKI, first 20 bytes, grouped). */
export async function fingerprintOf(publicKeyB64: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", unb64(publicKeyB64)));
  const hex = Array.from(hash.slice(0, 20), (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.toUpperCase().match(/.{1,4}/g)!.join(" ");
}

async function importPublic(publicKeyB64: string) {
  return crypto.subtle.importKey("spki", unb64(publicKeyB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function deriveWrapKey(priv: CryptoKey, peerPubB64: string, salt: Uint8Array, info: string) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: await importPublic(peerPubB64) }, priv, 256);
  const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export interface Recipient { deviceId: string; keyVersion: number; publicKeyB64: string }
export interface Envelope { s: string; i: string; k: string }
export interface EnvelopeSet { sv: number; r: Record<string, Envelope> }

const infoFor = (sender: string, sv: number, rcpt: string) => `bridgepro-v32|${sender}:${sv}|${rcpt}`;

export async function encryptMessage(
  plaintext: string,
  sender: { deviceId: string; keyVersion: number; privateKey: CryptoKey },
  recipients: Recipient[],
) {
  const contentKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, contentKey, enc.encode(plaintext));
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", contentKey));
  const r: Record<string, Envelope> = {};
  for (const rc of recipients) {
    const id = `${rc.deviceId}:${rc.keyVersion}`;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wiv = crypto.getRandomValues(new Uint8Array(12));
    const wk = await deriveWrapKey(sender.privateKey, rc.publicKeyB64, salt, infoFor(sender.deviceId, sender.keyVersion, id));
    const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv: wiv }, wk, raw);
    r[id] = { s: b64(salt), i: b64(wiv), k: b64(wrapped) };
  }
  raw.fill(0);
  return { ciphertext: b64(ct), iv: b64(iv), envelopes: { sv: sender.keyVersion, r } satisfies EnvelopeSet };
}

export async function decryptMessage(
  msg: { ciphertext: string; iv: string; envelopes: EnvelopeSet; senderDeviceId: string },
  me: { deviceId: string; keyVersion: number; privateKey: CryptoKey },
  senderPublicKeyB64: string,
): Promise<string> {
  const id = `${me.deviceId}:${me.keyVersion}`;
  const env = msg.envelopes?.r?.[id];
  if (!env) throw new Error("no-envelope");
  const wk = await deriveWrapKey(me.privateKey, senderPublicKeyB64, unb64(env.s), infoFor(msg.senderDeviceId, msg.envelopes.sv, id));
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(env.i) }, wk, unb64(env.k));
  const ck = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(msg.iv) }, ck, unb64(msg.ciphertext));
  return dec.decode(pt);
}