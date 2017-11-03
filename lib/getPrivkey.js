const crypto = require('./crypto')

module.exports = function getPrivkey (user, pass, callback) {
  crypto.hashPass(pass, user.salt, function (err, pwhash) {
    if (err) return callback(err)
    const sk = user.signKeys
    const ek = user.encryptKeys
    crypto.decrypt(sk.privkey, sk.nonce, pwhash.secret, function (err, signPrivkey) {
      if (err) return callback(err)
      crypto.decrypt(ek.privkey, ek.nonce, pwhash.secret, function (err, encryptPrivkey) {
        if (err) return callback(err)
        callback(null, signPrivkey, encryptPrivkey)
      })
    })
  })
}
