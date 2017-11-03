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

test('openCert', t => {
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

test('createUser validates type of pass', t => {
  t.throws(() => ident.createUser(123, {}, function () {}))
  t.end()
})

test('createUser validates length of pass', t => {
  t.throws(() => ident.createUser('x', {}, function () {}))
  t.end()
})

test('make the cert invalid, openCert fails', t => {
  ident.createUser('this is my passw3rd', {name: 'doug'}, function (err, user) {
    if (err) throw err
    user.cert = Buffer.alloc(64)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('make the expiration invalid, openCert fails', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'doug'}, function (err, user) {
    if (err) throw err
    ident.setExpiration(user, pass, Date.now() - 1000)
    t.throws(() => ident.openCert(user))
    t.end()
  })
})

test('setExpiration', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'pam'}, function (err, user) {
    if (err) throw err
    const expiration = ident.openCert(user).expiration
    ident.setExpiration(user, pass, Number(expiration) + 1000)
    const newExpiration = ident.openCert(user).expiration
    t.strictEqual(newExpiration, expiration + 1000)
    t.end()
  })
})

test('modifyIdentity', t => {
  const pass = '123!@#456$%6789&*('
  ident.createUser(pass, {name: 'ice king'}, function (err, user) {
    if (err) throw err
    const oldID = ident.openCert(user).id
    ident.modifyIdentity(user, pass, {name: 'princess bubblegum'})
    const newID = ident.openCert(user).id
    t.strictEqual(newID.name, 'princess bubblegum')
    t.strictEqual(oldID.name, 'ice king')
    t.end()
  })
})

test('changePass', t => {
  const pass1 = '123!@#456$%6789&*('
  const pass2 = '9183648374923641937'
  ident.createUser(pass1, {name: 'ja rule'}, function (err, user) {
    if (err) throw err
    ident.changePass(user, pass1, pass2, function (err, user) {
      if (err) throw err
      ident.modifyIdentity(user, pass2, {name: 'xzibit'})
      t.strictEqual(ident.openCert(user).id.name, 'xzibit')
      // Try to use the old pass -- we'll get an error and user is unchanged
      // t.throws(() => ident.modifyIdentity(user, pass1, {name: 'busta rhymes'}))
      // t.strictEqual(ident.openCert(user).id.name, 'xzibit')

      t.end()
    })
  })
})
