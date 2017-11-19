const assert = require('assert')
const crypto = require('../wot-crypto') // TODO

const ident = module.exports = {}

// Create keys, certs, and sigs for a new user
ident.createUser = function createUser (pass, ident, callback) {
  assert(pass && pass.length && typeof pass === 'string' && pass.length >= 7, 'pass in a string passphrase of length at least 7')
  assert(ident && typeof ident === 'object', 'pass in an object of identity data')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback')
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) return callback(err)
    const boxKeypair = crypto.createBoxKeypair(pwhash.secret)
    const signKeypair = crypto.createSignKeypair(pwhash.secret)
    const cert = JSON.stringify({
      expiration: Date.now() + 31556926000, // one year in future
      id: ident,
      lock: boxKeypair.pk.toString('hex'),
      imprint: signKeypair.pk.toString('hex')
    })
    const certSigned = crypto.sign(cert, signKeypair.sk)
    // Encrypt the signing private key and save the cipher/nonce
    const signSkEncrypted = crypto.encrypt(pwhash.secret, signKeypair.sk.toString('hex'))
    // Encrypt the encrypting private key and save the cipher/nonce
    const boxSkEncrypted = crypto.encrypt(pwhash.secret, boxKeypair.sk.toString('hex'))
    const user = {
      imprint: signKeypair.pk,
      stamp: signKeypair.sk,
      stamp_locked: signSkEncrypted,
      lock: boxKeypair.pk,
      key: boxKeypair.sk,
      key_locked: boxSkEncrypted,
      cert: certSigned,
      _salt: pwhash.salt
    }
    callback(null, user)
  })
}

ident.openCert = function openCert (user) {
  assert(user.imprint instanceof Buffer, 'user needs an imprint')
  assert(user.cert instanceof Buffer, 'user needs a cert')
  const plain = crypto.openSigned(user.cert, user.imprint)
  const cert = JSON.parse(plain)
  if (cert.expiration < Date.now()) throw new Error('User certification has expired')
  return cert
}

ident.setExpiration = function setExpiration (user, ts) {
  assert.strictEqual(typeof ts, 'number', 'timestamp must be a number')
  resetCert(user, 'expiration', ts)
  return user
}

ident.modifyIdentity = function modifyIdentity (user, info) {
  assert(info && typeof info === 'object', 'pass in an info object')
  resetCert(user, 'id', info)
  return user
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
// Used in setExpiration and modifyIdentity
function resetCert (user, prop, val) {
  assert(user.stamp instanceof Buffer, 'user must have an unlocked stamp (user.stamp)')
  const cert = ident.openCert(user)
  cert[prop] = val
  user.cert = crypto.sign(JSON.stringify(cert), user.stamp)
  return user
}

// Change the user's password (re-encrypt their secret keys using a new pass hash)
ident.changePass = function changePass (user, newPass, callback) {
  assert(user.stamp instanceof Buffer, 'user must have an unlocked stamp (user.stamp)')
  assert(newPass && typeof newPass === 'string' && newPass.length >= 7, 'passphrase must be a string with length at least 7')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback function')
  crypto.hashPass(newPass, null, function (err, pwhash) {
    if (err) return callback(err)
    user._salt = pwhash.salt
    user.stamp_locked = crypto.encrypt(pwhash.secret, user.stamp.toString('hex'))
    user.key_locked = crypto.encrypt(pwhash.secret, user.key.toString('hex'))
    callback(null, user)
  })
}
