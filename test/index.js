const test = require('tape')
const ident = require('../')

test('it generates user data', t => {
  ident.createUser('xyz xyz xyz', {name: 'partario'}, function (err, user) {
    if (err) throw err
    t.assert(ident.checkSig(user), 'sig is valid')
    t.strictEqual(typeof user.cert, 'string', 'saves ident json')
    t.assert(user.signKeys.pubkey)
    t.assert(user.signKeys.privkey)
    t.assert(user.encryptKeys.pubkey)
    t.assert(user.encryptKeys.privkey)
    t.assert(user.certSig instanceof Buffer)
    t.assert(user.salt instanceof Buffer)
  })
  t.end()
})
