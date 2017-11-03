const assert = require('assert')
const debug = require('debug')('wot-identity:crypto')
const sodium = require('sodium-universal')

module.exports = {}

// Get a secret key from a password
module.exports.hashPass = function getKey (pass, salt, callback) {
  debug('hashing password')
  assert(pass.length > 0, 'pass password')
  assert.strictEqual(typeof callback, 'function', 'pass callback')

  const output = sodium.malloc(32) // equal to crypto_box_SEEDBYTES and crypto_sign_SEEDBYTES
  if (!salt) {
    salt = sodium.malloc(sodium.crypto_pwhash_SALTBYTES)
    sodium.randombytes_buf(salt)
  }
  sodium.crypto_pwhash_async(
    output,
    Buffer.from(pass),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, // ops limit
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, // mem limit
    sodium.crypto_pwhash_ALG_DEFAULT, // algorithm
    function (err) {
      if (err) return callback(err)
      callback(null, {salt: salt, secret: output})
    }
  )
}

// Encrypt text using a pass
module.exports.encrypt = function encrypt (key, message) {
  debug('encrypting message with key')
  key = Buffer.from(key)
  message = Buffer.from(message)
  const cipher = sodium.malloc(message.length + sodium.crypto_secretbox_MACBYTES)
  const nonce = sodium.malloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  sodium.crypto_secretbox_easy(cipher, message, nonce, key)
  return {cipher: cipher, nonce: nonce}
}

module.exports.decrypt = function decrypt (cipher, nonce, key) {
  key = Buffer.from(key)
  const plaintext = sodium.malloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
  const result = sodium.crypto_secretbox_open_easy(plaintext, cipher, nonce, key)
  if (!result) throw new Error('Unable to decrypt')
  return plaintext
}

module.exports.signKeyPair = function signKeyPair (seed) {
  debug('creating pub/priv key pair for signing')
  const pubkey = sodium.malloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const privkey = sodium.malloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pubkey, privkey, seed)
  return {pubkey: pubkey, privkey: privkey}
}

module.exports.boxKeyPair = function boxKeyPair (seed) {
  debug('creating pub/priv key pair for encryption')
  const pubkey = sodium.malloc(sodium.crypto_box_PUBLICKEYBYTES)
  const privkey = sodium.malloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_box_seed_keypair(pubkey, privkey, seed)
  return {pubkey: pubkey, privkey: privkey}
}

module.exports.sign = function sign (message, key) {
  debug('signing text')
  message = Buffer.from(message)
  const signed = sodium.malloc(message.length + sodium.crypto_sign_BYTES)
  sodium.crypto_sign(signed, message, key)
  return signed
}
