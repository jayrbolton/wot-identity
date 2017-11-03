const debug = require('debug')('wot-identity:core')
const assert = require('assert')
const sodium = require('sodium-universal')
const crypto = require('./lib/crypto')

var ident = module.exports = {}

// Create keys, certs, and sigs for a new user
ident.createUser = function createUser (passphrase, ident, callback) {
  debug('creating a new user identity')
  assert.strictEqual(typeof passphrase, 'string', 'passhprase should be a string')
  assert(passphrase.length >= 7, 'passphrase must have length at least 7')
  assert(typeof ident === 'object' && ident !== null, 'pass in an object of identity data that can be stringified')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback')

  debug('creating secret key from passphrase')
  crypto.hashPass(passphrase, null, function (err, pwhash) {
    if (err) return callback(err)
    debug('creating sign and encrypt keypairs')
    const encryptKeyPair = crypto.boxKeyPair(pwhash.secret)
    const signKeyPair = crypto.signKeyPair(pwhash.secret)
    debug('generating cert')
    const cert = JSON.stringify({
      expiration: Date.now() + 31556926000, // one year in future
      algo: 'Ed25519',
      id: ident,
      encryptPub: encryptKeyPair.pubkey.toString('hex'),
      signPub: signKeyPair.pubkey.toString('hex')
    })
    const certSigned = crypto.sign(cert, signKeyPair.privkey)
    // Encrypt the signing private key and save the cipher/nonce
    const signPrivEncrypted = crypto.encrypt(pwhash.secret, signKeyPair.privkey)
    // Encrypt the encrypting private key and save the cipher/nonce
    const encryptPrivEncrypted = crypto.encrypt(pwhash.secret, encryptKeyPair.privkey)
    const user = {
      signKeys: {
        pubkey: signKeyPair.pubkey,
        privkey: signPrivEncrypted.cipher,
        privkey_plain: signKeyPair.privkey,
        nonce: signPrivEncrypted.nonce
      },
      encryptKeys: {
        pubkey: encryptKeyPair.pubkey,
        privkey: encryptPrivEncrypted.cipher,
        privkey_plain: signKeyPair.privkey,
        nonce: encryptPrivEncrypted.nonce
      },
      cert: certSigned,
      salt: pwhash.salt
    }
    callback(null, user)
  })
}

ident.openCert = function openCert (user) {
  debug('checking and opening a user certification')
  assert(user.signKeys && user.signKeys.privkey instanceof Buffer, 'user needs a signing key')
  assert(user.cert && user.cert instanceof Buffer, 'user needs a cert')
  const cert = sodium.malloc(user.cert.length - sodium.crypto_sign_BYTES)
  const result = sodium.crypto_sign_open(cert, user.cert, user.signKeys.pubkey)
  if (!result) throw new Error('User certification is invalid')
  const obj = JSON.parse(cert.toString('utf8'))
  if (obj.expiration < Date.now()) throw new Error('User certification has expired')
  return obj
}

ident.setExpiration = function setExpiration (user, pass, ts) {
  debug('extending expiration for a user\'s cert')
  assert.strictEqual(typeof ts, 'number', 'timestamp must be a number')
  resetCert(user, user.signKeys.privkey_plain, 'expiration', ts)
  return user
}

ident.modifyIdentity = function modifyIdentity (user, pass, info) {
  debug('changing the identity information for a user')
  resetCert(user, user.signKeys.privkey_plain, 'id', info)
  return user
}

ident.changePass = function changePass (user, oldPass, newPass, callback) {
  debug('changing user password')
  assert(newPass.length >= 7, 'passphrase must have length at least 7')
  crypto.hashPass(newPass, null, function (err, pwhash) {
    if (err) return callback(err)
    const signPrivEncrypted = crypto.encrypt(pwhash.secret, user.signKeys.privkey_plain)
    const encryptPrivEncrypted = crypto.encrypt(pwhash.secret, user.encryptKeys.privkey_plain)
    user.signKeys.privkey = signPrivEncrypted.cipher
    user.signKeys.nonce = signPrivEncrypted.nonce
    user.encryptKeys.privkey = encryptPrivEncrypted.cipher
    user.encryptKeys.nonce = encryptPrivEncrypted.nonce
    user.salt = pwhash.salt
    callback(null, user)
  })
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
function resetCert (user, privkey, prop, val) {
  const cert = ident.openCert(user)
  cert[prop] = val
  user.cert = crypto.sign(JSON.stringify(cert), privkey)
  return user
}
