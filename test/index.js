const crypto = require('../../wot-crypto') // TODO
const test = require('tape')
const ident = require('../')
const fill = require('buffer-fill')

test('creates a user with various properties present', t => {
  ident.createUser('xyz xyz xyz', {name: 'partario'}, function (err, user) {
    if (err) throw err
    t.assert(user.signKeys.pk instanceof Buffer, 'creates public signing key')
    t.assert(typeof user.signKeys.sk_encrypted === 'string', 'creates secret encrypted signing key')
    t.assert(user.signKeys.sk_plain instanceof Buffer, 'creates secret plain signing key')
    t.assert(user.boxKeys.pk instanceof Buffer, 'creates public box key')
    t.assert(typeof user.boxKeys.sk_encrypted === 'string', 'creates secret encrypted box key')
    t.assert(user.boxKeys.sk_plain instanceof Buffer, 'creates secret plain box key')
    t.assert(user.cert instanceof Buffer, 'creates user cert')
    t.assert(user.salt instanceof Buffer, 'creates user pwhash salt')
    t.end()
  })
})

test('can open a valid cert as an obj', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    const cert = ident.openCert(user)
    t.strictEqual(cert.id.name, 'doug', 'cert contains nested id info')
    t.strictEqual(cert.boxPub.length, 64, 'cert contains the box pub key')
    t.strictEqual(cert.signPub.length, 64, 'cert contains the sign pub key')
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
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'finn'}, function (err, user) {
    if (err) throw err
    user.signKeys.pk = fill(Buffer.alloc(32), 'xyz')
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('setExpiration', t => {
  const pass = '123!@#456$%6789&*('
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
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'doug'}, function (err, user) {
    if (err) throw err
    ident.setExpiration(user, Date.now() - 1000)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('modifyIdentity', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'jim halpert'}, function (err, user) {
    if (err) throw err
    const id = ident.openCert(user).id
    id.age = 33
    ident.modifyIdentity(user, id)
    const newID = ident.openCert(user).id
    t.strictEqual(newID.name, 'jim halpert')
    t.strictEqual(newID.age, 33)
    t.end()
  })
})

test('changePass', t => {
  const pass1 = '123!@#456$%6789&*('
  const pass2 = '9183648374923641937'
  ident.createUser(pass1, {name: 'ja rule'}, function (err, user) {
    if (err) throw err
    const oldSalt = user.salt
    ident.changePass(user, pass2, function (err, user) {
      if (err) throw err
      const newSalt = user.salt
      crypto.hashPass(pass1, oldSalt, function (err, pwhash1) {
        if (err) throw err
        crypto.hashPass(pass2, newSalt, function (err, pwhash2) {
          if (err) throw err
          const boxSk = crypto.decrypt(pwhash2.secret, user.boxKeys.sk_encrypted, 'successfully decrypts secret box key using new pass hash')
          const signSk = crypto.decrypt(pwhash2.secret, user.signKeys.sk_encrypted, 'successfully decrypts secret sign key using new pass hash')
          t.strictEqual(signSk.toString('hex'), user.signKeys.sk_plain.toString('hex'))
          t.strictEqual(boxSk.toString('hex'), user.boxKeys.sk_plain.toString('hex'))
          t.throws(() => crypto.decrypt(pwhash1.secret, user.signKeys.sk_encrypted), 'throws when trying to decrypt secret sign key with the old pass')
          t.throws(() => crypto.decrypt(pwhash1.secret, user.boxKeys.sk_encrypted), 'throws when trying to decrypt secret box key with old pass')
          t.end()
        })
      })
    })
  })
})
