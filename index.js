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
      boxPub: boxKeypair.pk.toString('hex'),
      signPub: signKeypair.pk.toString('hex')
    })
    const certSigned = crypto.sign(cert, signKeypair.sk)
    // Encrypt the signing private key and save the cipher/nonce
    const signSkEncrypted = crypto.encrypt(pwhash.secret, signKeypair.sk.toString('hex'))
    // Encrypt the encrypting private key and save the cipher/nonce
    const boxSkEncrypted = crypto.encrypt(pwhash.secret, boxKeypair.sk.toString('hex'))
    const user = {
      signKeys: {
        pk: signKeypair.pk,
        sk_encrypted: signSkEncrypted,
        sk_plain: signKeypair.sk
      },
      boxKeys: {
        pk: boxKeypair.pk,
        sk_encrypted: boxSkEncrypted,
        sk_plain: boxKeypair.sk
      },
      cert: certSigned,
      salt: pwhash.salt
    }
    callback(null, user)
  })
}

ident.openCert = function openCert (user) {
  assert(user.signKeys && user.signKeys.pk instanceof Buffer, 'user needs a signing public key')
  assert(user.cert && user.cert instanceof Buffer, 'user needs a cert')
  const plain = crypto.openSigned(user.cert, user.signKeys.pk)
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
  resetCert(user, 'id', info)
  return user
}

// Change some property in a user's cert using a setter function which takes the old property as a param
// resign the newcert and modify the user's cert and certSig props
// Used in setExpiration and modifyIdentity
function resetCert (user, prop, val) {
  assert(user.signKeys.sk_plain, 'user must have a plain secret signing key (user.signKeys.sk_plain)')
  const cert = ident.openCert(user)
  cert[prop] = val
  user.cert = crypto.sign(JSON.stringify(cert), user.signKeys.sk_plain)
  return user
}

// Change the user's password (re-encrypt their secret keys using a new pass hash)
ident.changePass = function changePass (user, newPass, callback) {
  assert(user && user.signKeys.sk_plain.length && user.boxKeys.sk_plain, 'pass in a user with all keys')
  assert(newPass && newPass.length >= 7, 'passphrase must have length at least 7')
  assert.strictEqual(typeof callback, 'function', 'pass in a callback function')
  crypto.hashPass(newPass, null, function (err, pwhash) {
    if (err) return callback(err)
    user.salt = pwhash.salt
    user.signKeys.sk_encrypted = crypto.encrypt(pwhash.secret, user.signKeys.sk_plain.toString('hex'))
    user.boxKeys.sk_encrypted = crypto.encrypt(pwhash.secret, user.boxKeys.sk_plain.toString('hex'))
    callback(null, user)
  })
}
