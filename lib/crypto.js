const assert = require('assert')
const debug = require('debug')('wot-identity:crypto')
const sodium = require('sodium-universal')

module.exports = {}

// Get a secret key from a password
module.exports.hashPass = function getKey (pass, callback) {
  debug('hashing password')
  assert(pass.length, 'pass password')
  assert(typeof callback, 'function', 'pass callback')

  const output = sodium.malloc(32) // equal to crypto_box_SEEDBYTES and crypto_sign_SEEDBYTES
  const salt = sodium.malloc(sodium.crypto_pwhash_SALTBYTES)
  sodium.randombytes_buf(salt)
  sodium.mlock(salt)
  sodium.crypto_pwhash_async(
    output,
    Buffer.from(pass),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, // ops limit
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, // mem limit
    sodium.crypto_pwhash_ALG_DEFAULT, // algorithm
    function (err) {
      sodium.mlock(output)
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
  sodium.mlock(nonce)

  sodium.crypto_secretbox_easy(cipher, message, nonce, key)
  sodium.mlock(cipher)
  return cipher
}

module.exports.signKeyPair = function signKeyPair (seed) {
  const pubkey = sodium.malloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const privkey = sodium.malloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pubkey, privkey, seed)
  sodium.mlock(pubkey)
  sodium.mlock(privkey)
  return {pubkey: pubkey, privkey: privkey}
}

module.exports.boxKeyPair = function boxKeyPair (seed) {
  const pubkey = sodium.malloc(sodium.crypto_box_PUBLICKEYBYTES)
  const privkey = sodium.malloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_box_seed_keypair(pubkey, privkey, seed)
  sodium.mlock(pubkey)
  sodium.mlock(privkey)
  return {pubkey: pubkey, privkey: privkey}
}

module.exports.hashAndSign = function hashAndSign (txt, key) {
  debug('hashing and signing text')
  txt = Buffer.from(txt)
  key = Buffer.from(key)
  const hash = sodium.malloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(hash, txt)
  sodium.mlock(hash)
  const signedMessage = sodium.malloc(sodium.crypto_sign_BYTES + hash.length)
  sodium.crypto_sign(signedMessage, hash, key)
  return signedMessage
}
