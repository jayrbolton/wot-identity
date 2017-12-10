const crypto = require('../../wot-crypto') // TODO
const test = require('tape')
const ident = require('../')
const fill = require('buffer-fill')

test('.createUser creates a user with various properties present', t => {
  ident.createUser('xyz xyz xyz', {name: 'partario'}, function (err, user) {
    if (err) throw err
    t.strictEqual(user.id.length, 64, 'creates public signing key')
    t.strictEqual(user.thumbprint.length, 64, 'creates public signing key')
    t.strictEqual(user.thumb_locked.length, 337, 'creates secret encrypted signing key')
    t.strictEqual(user.thumb.length, 128, 'creates secret plain signing key')
    t.strictEqual(user.key.length, 64, 'creates public box key')
    t.strictEqual(user.key_locked.length, 209, 'creates secret encrypted box key')
    t.ok(user.cert.length, 'creates user cert')
    t.strictEqual(user._salt.length, 32, 'creates user pwhash salt')
    t.end()
  })
})

test('.openCert can open a valid cert into an obj', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    const cert = ident.openCert(user)
    t.strictEqual(cert.id.length, 64, 'cert generates an id')
    t.strictEqual(cert.profile.name, 'doug', 'cert contains nested id info')
    t.strictEqual(cert.lock.length, 64, 'cert contains the lock')
    t.strictEqual(cert.thumbprint.length, 64, 'cert contains the thumbprint')
    t.assert(cert.expiration > Date.now(), 'cert expiration is in future')
    t.end()
  })
})

test('createUser validates type of pass', t => {
  t.throws(() => ident.createUser(123, {}, function () {}))
  t.end()
})

test('createUser validates length of pass', t => {
  t.throws(() => ident.createUser('x', {}, function () {}))
  t.end()
})

test('with an invalid cert, openCert throws', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    user.cert = Buffer.alloc(64)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('with an invalid sign pub key, openCert throws', t => {
  const pass = crypto.id(8)
  ident.createUser(pass, {name: 'finn'}, function (err, user) {
    if (err) throw err
    user.thumbprint = fill(Buffer.alloc(32), 'xyz')
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('setExpiration', t => {
  const pass = crypto.id(8)
  ident.createUser(pass, {name: 'pam beasley'}, function (err, user) {
    if (err) throw err
    const expiration = ident.openCert(user).expiration
    ident.setExpiration(user, Number(expiration) + 1000)
    const newExpiration = ident.openCert(user).expiration
    t.strictEqual(newExpiration, expiration + 1000)
    t.end()
  })
})

test('make the expiration invalid, openCert fails', t => {
  const pass = crypto.id(8)
  ident.createUser(pass, {name: 'doug'}, function (err, user) {
    if (err) throw err
    ident.setExpiration(user, Date.now() - 1000)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('modifyIdentity', t => {
  const pass = crypto.id(8)
  ident.createUser(pass, {name: 'jim halpert'}, function (err, user) {
    if (err) throw err
    const profile = ident.openCert(user).profile
    profile.age = 33
    ident.modifyProfile(user, profile)
    const newProfile = ident.openCert(user).profile
    t.strictEqual(newProfile.name, 'jim halpert')
    t.strictEqual(newProfile.age, 33)
    t.end()
  })
})

test('changePass', t => {
  const pass1 = crypto.id(8)
  const pass2 = crypto.id(8)
  ident.createUser(pass1, {name: 'ja rule'}, function (err, user) {
    if (err) throw err
    const oldSalt = user._salt
    ident.changePass(user, pass2, function (err, user) {
      if (err) throw err
      const newSalt = user._salt
      crypto.hashPass(pass1, oldSalt, function (err, pwhash1) {
        if (err) throw err
        crypto.hashPass(pass2, newSalt, function (err, pwhash2) {
          if (err) throw err
          const boxSk = crypto.decrypt(pwhash2.secret, user.key_locked, 'successfully opens the locked key using new pass hash')
          const signSk = crypto.decrypt(pwhash2.secret, user.thumb_locked, 'successfully opens the locked thumb using new pass hash')
          t.strictEqual(signSk.toString('hex'), user.thumb.toString('hex'))
          t.strictEqual(boxSk.toString('hex'), user.key.toString('hex'))
          t.throws(() => crypto.decrypt(pwhash1.secret, user.thumb_locked), 'throws when trying to decrypt secret sign key with the old pass')
          t.throws(() => crypto.decrypt(pwhash1.secret, user.key_locked), 'throws when trying to decrypt secret box key with old pass')
          t.end()
        })
      })
    })
  })
})

test('.signUser and .verifySignedUser: one user can sign another users cert', t => {
  ident.createUser('xyz xyz xyz', {name: 'A'}, function (err, signer) {
    if (err) throw err
    ident.createUser('xyz xyz xyz', {name: 'B'}, function (err, signee) {
      if (err) throw err
      const signedSigneeCert = ident.signUser(signer, signee)
      ident.verifySignedUser(signer, signee, signedSigneeCert)
      t.end()
    })
  })
})
