// Confidentiality: the user encrypts the whole file BEFORE anything leaves their machine.
// AES-256-GCM = encryption + an authentication tag (tamper detection).
//
// blob layout:  iv (12 bytes) || ciphertext (same length as file) || GCM tag (16 bytes)
// The blob is what gets chunked, Merkled and stored by the provider. The key stays with
// the user only. Without the key, the provider and anyone reading the chain just see
// random-looking bytes.
const crypto = require("crypto");

function newKey() {
  return crypto.randomBytes(32);
}

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12); // fresh random IV for every file (never reuse with the same key)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]);
}

function decrypt(blob, key) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]); // throws if anything was altered
}

module.exports = { newKey, encrypt, decrypt };
