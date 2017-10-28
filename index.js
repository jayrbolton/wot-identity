const debug = require('debug')('wot-identity')
const assert = require('assert')
const crypto = require('./lib/crypto')
const sodium = require('sodium-universal')

module.exports = {}

// Create keys, certs, and sigs for a new user
module.exports.createUser = function createUser (passphrase, ident, callback) {
  debug('creating a new user identity')
  assert.strictEqual(typeof passphrase, 'string', 'passhprase should be a string')
  assert(typeof ident === 'object' && ident !== null, 'pass in an object of identity data that can be stringified')
  assert(passphrase.length >= 7, 'passphrase must have length at least 7')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback')

  debug('creating secret key from passphrase')
  crypto.hashPass(passphrase, function (err, pwhash) {
    if (err) return callback(err)
    debug('creating sign and encrypt keypairs')
    const encryptKeys = crypto.boxKeyPair(pwhash.secret)
    const signKeys = crypto.signKeyPair(pwhash.secret)
    debug('generating cert')
    const cert = JSON.stringify({
      expiration: Date.now() + 31556926000,
      algo: 'Ed25519',
      id: ident,
      encryptPub: encryptKeys.pubkey.toString('hex'),
      signPub: signKeys.pubkey.toString('hex')
    })
    debug('hashing and signing certificate')
    const certSig = crypto.hashAndSign(cert, signKeys.privkey)
    signKeys.privkey = crypto.encrypt(pwhash.secret, signKeys.privkey)
    encryptKeys.privkey = crypto.encrypt(pwhash.secret, encryptKeys.privkey)
    const user = {
      signKeys: signKeys,
      encryptKeys: encryptKeys,
      cert: cert,
      certSig: certSig,
      salt: pwhash.salt
    }
    callback(null, user)
  })
}

// Validate the self-signature for a user's certificate
// The self-signature is the hash of the cert signed by the user's privkey
// So the cert can be decrypted using the user's pubkey
// if the decrypted cert matches the given cert, it is validated
// Returns boolean
module.exports.checkSig = function checkSig (user, callback) {
  debug('checking a user\'s certification signature')
  assert(user.signKeys && user.signKeys.privkey && (user.signKeys.privkey instanceof Buffer), 'user needs a private signing key')
  assert(user.cert && typeof user.cert === 'string', 'user needs a cert property')
  assert(user.certSig && (user.certSig instanceof Buffer), 'user needs a cert signature')
  return sodium.crypto_sign_open(Buffer.from(user.cert), user.certSig, user.signKeys.pubkey)
}

module.exports.extendExpiration = function extendExpiration (user, ms) {
  debug('extending expiration for a user\'s cert')
  assert(ms > 0, 'ms must be a number greater than 0')
  return resetCert(user, 'expiration', (exp) => exp + ms)
}

module.exports.modifyIdentity = function modifyIdentity (user, info, callback) {
  debug('modifying user cert identification information')
  assert(info !== null && typeof info === 'object', 'pass in an object of new identity info')
  return resetCert(user, 'id', () => JSON.stringify(info))
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
function resetCert (user, prop, setterFn) {
  assert(user.signKeys && user.signKeys.privkey && (user.signKeys.privkey instanceof Buffer), 'user must have a private signing key')
  assert(user.cert, 'user must have a cert')
  assert(user.certSig, 'user must have a cert')
  var cert = JSON.parse(user.cert)
  cert[prop] = setterFn(cert[prop])
  cert = JSON.stringify(cert)
  user.cert = cert
  user.certSig = crypto.hashAndSign(cert, user.privkey)
  return user
}
