const test = require('tape')
const ident = require('../')

test('createUser', t => {
  ident.createUser('xyz xyz xyz', {name: 'partario'}, function (err, user) {
    if (err) throw err
    t.assert(user.signKeys.pubkey instanceof Buffer)
    t.assert(user.signKeys.privkey instanceof Buffer)
    t.assert(user.encryptKeys.pubkey instanceof Buffer)
    t.assert(user.encryptKeys.privkey instanceof Buffer)
    t.assert(user.cert instanceof Buffer)
    t.assert(user.salt instanceof Buffer)
    t.end()
  })
})

test('createUser, openCert', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    const cert = ident.openCert(user)
    t.strictEqual(cert.id.name, 'doug')
    t.strictEqual(cert.encryptPub.length, 64)
    t.strictEqual(cert.signPub.length, 64)
    t.strictEqual(cert.algo, 'Ed25519')
    t.assert(cert.expiration > Date.now())
    t.end()
  })
})

test('craeteUser validates type of pass', t => {
  t.throws(() => ident.createUser(123, {}, function () {}))
  t.end()
})

test('createUser validates length of pass', t => {
  t.throws(() => ident.createUser('x', {}, function () {}))
  t.end()
})

test('createUser, make the cert invalid, openCert fails', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    user.cert = Buffer.alloc(64)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test.only('createUser, make the expiration invalid, openCert fails', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'doug'}, function (err, user) {
    if (err) throw err
    ident.extendExpiration(user, pass, -31556926000, function (err, user) {
      if (err) throw err
      t.throws(() => ident.openCert(user))
      t.end()
    })
  })
})

test('createUser, extendExpiration', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'pam'}, function (err, user) {
    if (err) throw err
    const expiration = ident.openCert(user).expiration
    ident.extendExpiration(user, pass, 1000, function (err, user) {
      if (err) throw err
      const newExpiration = ident.openCert(user).expiration
      t.strictEqual(newExpiration, expiration + 1000)
      t.end()
    })
  })
})

test('createUser, modifyIdentity', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'ice king'}, function (err, user) {
    if (err) throw err
    const oldID = ident.openCert(user).id
    ident.modifyIdentity(user, pass, {name: 'princess bubblegum'}, function (err, user) {
      if (err) throw err
      const newID = ident.openCert(user).id
      t.strictEqual(newID.name, 'princess bubblegum')
      t.strictEqual(oldID.name, 'ice king')
      t.end()
    })
  })
})
