const assert = require('assert')
const crypto = require('../wot-crypto') // TODO

const ident = module.exports = {}

// Create keys, certs, and sigs for a new user
ident.createUser = function createUser (pass, profile, callback) {
  assert(pass && pass.length && typeof pass === 'string' && pass.length >= 7, 'pass in a string passphrase of length at least 7')
  assert(profile && typeof profile === 'object', 'pass in an object of profile data')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback')
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) return callback(err)
    const boxKeypair = crypto.createBoxKeypair(pwhash.secret)
    const signKeypair = crypto.createSignKeypair(pwhash.secret)
    const id = crypto.id(32)
    const cert = JSON.stringify({
      expiration: Date.now() + 31556926000, // one year in future
      profile: profile,
      id: id,
      lock: boxKeypair.pk,
      thumbprint: signKeypair.pk
    })
    const certSigned = crypto.sign(cert, signKeypair.sk)
    // Encrypt the signing secret key and save the cipher/nonce
    const signSkEncrypted = crypto.encrypt(pwhash.secret, signKeypair.sk)
    // Encrypt the encrypting secret key and save the cipher/nonce
    const boxSkEncrypted = crypto.encrypt(pwhash.secret, boxKeypair.sk)
    const user = {
      id: id,
      thumbprint: signKeypair.pk,
      thumb: signKeypair.sk,
      thumb_locked: signSkEncrypted,
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
  assert(user.thumbprint && user.thumbprint.length, 'user needs an thumbprint')
  assert(user.cert && user.cert.length, 'user needs a cert')
  const plain = crypto.openSigned(user.cert, user.thumbprint)
  const cert = JSON.parse(plain)
  if (cert.expiration < Date.now()) throw new Error('User certification has expired')
  return cert
}

ident.setExpiration = function setExpiration (user, ts) {
  assert.strictEqual(typeof ts, 'number', 'timestamp must be a number')
  resetCert(user, 'expiration', ts)
  return user
}

ident.modifyProfile = function modifyProfile (user, profile) {
  assert(profile && typeof profile === 'object', 'pass in a profile object')
  resetCert(user, 'profile', profile)
  return user
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
// Used in setExpiration and modifyIdentity
function resetCert (user, prop, val) {
  assert(user.thumb, user.thumb.length, 'user must have a .thumb')
  const cert = ident.openCert(user)
  cert[prop] = val
  user.cert = crypto.sign(JSON.stringify(cert), user.thumb)
  return user
}

// Change the user's password (re-encrypt their secret keys using a new pass hash)
ident.changePass = function changePass (user, newPass, callback) {
  assert(user.thumb && user.thumb.length, 'user must have a .thumb')
  assert(newPass && typeof newPass === 'string' && newPass.length >= 7, 'passphrase must be a string with length at least 7')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback function')
  crypto.hashPass(newPass, null, function (err, pwhash) {
    if (err) return callback(err)
    user._salt = pwhash.salt
    user.thumb_locked = crypto.encrypt(pwhash.secret, user.thumb)
    user.key_locked = crypto.encrypt(pwhash.secret, user.key)
    callback(null, user)
  })
}

// Have one user thumb another user's certification, to verify the identity is valid
ident.signUser = function signUser (signer, signee) {
  assert(signer.thumb && signer.thumb.length, 'the signer user needs a .thumb')
  ident.openCert(signee) // open it just to verify it
  return crypto.hashAndSign(signee.cert, signer.thumb)
}

// Given a user that has signed another user's cert
// and given the full certificate of the other user
// Verify that the signer is valid
ident.verifySignedUser = function verifySignedUser (signer, signee, signedHash) {
  // .openCert will throw an error if the cert is invalid
  const signeeCert = ident.openCert(signee)
  crypto.unhashAndVerify(signedHash, signee.cert, signer.thumbprint)
  return signeeCert
}
