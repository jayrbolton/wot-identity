const debug = require('debug')('wot-identity:core')
const assert = require('assert')
const crypto = require('./lib/crypto')
const sodium = require('sodium-universal')

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
        nonce: signPrivEncrypted.nonce
      },
      encryptKeys: {
        pubkey: encryptKeyPair.pubkey,
        privkey: encryptPrivEncrypted.cipher,
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

ident.extendExpiration = function extendExpiration (user, pass, ms, callback) {
  debug('extending expiration for a user\'s cert')
  assert.strictEqual(typeof ms, 'number', 'ms must be a number greater than 0')
  getPrivkey(user, pass, function (err, privkey) {
    if (err) return callback(err)
    resetCert(user, privkey, 'expiration', (exp) => exp + ms)
    callback(null, user)
  })
  // return resetCert(user, 'expiration', (exp) => exp + ms)
}

ident.modifyIdentity = function modifyIdentity (user, pass, info, callback) {
  debug('changing the identity information for a user')
  getPrivkey(user, pass, function (err, privkey) {
    if (err) return callback(err)
    resetCert(user, privkey, 'id', () => info)
    callback(null, user)
  })
}

function getPrivkey (user, pass, callback) {
  crypto.hashPass(pass, user.salt, function (err, pwhash) {
    if (err) return callback(err)
    const privkey = crypto.decrypt(user.signKeys.privkey, user.signKeys.nonce, pwhash.secret)
    debug('got privkey')
    callback(null, privkey)
  })
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
function resetCert (user, privkey, prop, setterFn) {
  const cert = ident.openCert(user)
  cert[prop] = setterFn(cert[prop])
  user.cert = crypto.sign(JSON.stringify(cert), privkey)
  return user
}
