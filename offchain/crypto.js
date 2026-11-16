// Confidentiality: the user encrypts the file BEFORE it leaves their machine.
// AES-256-GCM = encryption + tamper detection.
// blob = iv (12 bytes) || ciphertext || auth tag (16 bytes). The blob is what gets chunked and stored.
const crypto = require("crypto");

const newKey = () => crypto.randomBytes(32);

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12); // fresh random IV per file
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

function decrypt(blob, key) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]); // throws if altered
}

module.exports = { newKey, encrypt, decrypt };
