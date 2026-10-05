/**
 * Device identity: a non-extractable private key lives in IndexedDB on this
 * browser; only the public key + fingerprint are registered with the backend.
 */
import { supabase } from "@/integrations/supabase/client";
import { generateDeviceKeyPair } from "./crypto";

const DB = "bridgepro-v32";
const STORE = "device";

interface StoredDevice {
  userId: string;
  deviceId: string;
  keyVersion: number;
  privateKey: CryptoKey;
  publicKeyB64: string;
  fingerprint: string;
}

function db(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idb<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const d = await db();
  return new Promise((res, rej) => {
    const req = fn(d.transaction(STORE, mode).objectStore(STORE));
    req.onsuccess = () => res(req.result as T);
    req.onerror = () => rej(req.error);
  });
}

export const getLocalDevice = (userId: string) => idb<StoredDevice | undefined>("readonly", (s) => s.get(userId));
const putLocalDevice = (d: StoredDevice) => idb("readwrite", (s) => s.put(d, d.userId));
export const clearLocalDevice = (userId: string) => idb("readwrite", (s) => s.delete(userId));

function deviceName() {
  const ua = navigator.userAgent;
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "جهاز";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox/.test(ua) ? "Firefox" : /Chrome/.test(ua) ? "Chrome" : /Safari/.test(ua) ? "Safari" : "متصفح";
  return `${br} على ${os}`;
}

/** Ensures this browser has a registered, non-revoked device. */
export async function ensureDevice(userId: string): Promise<StoredDevice> {
  const local = await getLocalDevice(userId);
  if (local) {
    const { data } = await supabase.from("devices").select("id, revoked_at, key_version, public_identity_key").eq("id", local.deviceId).maybeSingle();
    if (data && !data.revoked_at && data.public_identity_key === local.publicKeyB64) return local;
    await clearLocalDevice(userId); // revoked or mismatched → re-enrol
  }
  const kp = await generateDeviceKeyPair();
  const { data, error } = await supabase
    .from("devices")
    .insert({ user_id: userId, name: deviceName(), public_identity_key: kp.publicKeyB64, fingerprint: kp.fingerprint })
    .select("id, key_version")
    .single();
  if (error || !data) throw new Error("تعذّر تسجيل هذا الجهاز");
  const stored: StoredDevice = { userId, deviceId: data.id, keyVersion: data.key_version, ...kp };
  await putLocalDevice(stored);
  return stored;
}

export async function rotateLocalKey(userId: string) {
  const local = await getLocalDevice(userId);
  if (!local) throw new Error("لا يوجد جهاز محلي");
  const kp = await generateDeviceKeyPair();
  const { error } = await supabase.rpc("rotate_device_key", { _device: local.deviceId, _public_key: kp.publicKeyB64, _fingerprint: kp.fingerprint });
  if (error) throw new Error("تعذّر تدوير المفتاح");
  await putLocalDevice({ ...local, ...kp, keyVersion: local.keyVersion + 1 });
}