# wot-identity

Public key cryptography for user identity with libsodium; part of [node-wot](https://github.com/jayrbolton/node-wot).

This library uses different, easier-to-use terms for key management, found in the paper [Why King George III Can Encrypt](http://randomwalker.info/teaching/spring-2014-privacy-technologies/king-george-iii-encrypt.pdf).

This module generates some of the initial user identity stuff, such as the keypair, certification, and self-signature. It also has two simple functions for locking and stamping a message. Save a user to disk with `wot-serialize`.

- Generate all the necessary data for a user
- Create a self-stamped user identity certificate
- Create locked versions of the stamp and the key for storage
- Utilities for updating the user, sending locked messages, or stamping messages

## createUser(passphrase, profile, callback)

Create a new user. `passphrase` can be any string of at least length 7.

`profile` should be an object that can be auto-converted to JSON with `JSON.stringify`. It can contain anything like name, aliases, website, email, dat addresses, etc.

`callback` receives two arguments: `err` and `user`.

`user` is an object with these properties:

- `stamp` - private buffer for stamping messages
- `stamp_locked` - locked stamp for storage (see `wot-serialize`)
- `imprint` - public imprint for others to verify a stamped message
- `key` - private key for unlocking locked messages
- `key_locked` - locked key for storage (see `wot-serialize`)
- `lock` - public lock to allow anyone to lock a message
- `cert`: a buffer of the stamped user certification

## openCert(user)

Open and validate the user's certification using their imprint. Will return an object of data for their cert. If the cert is invalid, either because the imprint doesn't match or because the cert is expired, then an error will be thrown.

```
const cert = ident.openCert(user)
t.strictEqual(cert.id.name, 'doug', 'cert contains nested id info')
t.strictEqual(cert.lock.length, 64, 'cert contains the lock')
t.strictEqual(cert.imprint.length, 64, 'cert contains the imprint')
```

Each cert has these properties;

- `id` - a large, random, probably unique for the user
- `expiration` - date at which this certification should be considered invalid
- `lock` - the user's public lock
- `imprint` - the user's public imprint
- `profile` - the profile data for the user (can be any json object)

## setExpiration(user, ms)

Set the expiration date for the user's certificate. The cert will get updated and resigned.

The `user` object must have properties for `signKeys`, `cert`.

## modifyProfile(user, profile, callback)

Modify the profile info for a user. `profile` should be an object that can be converted to JSON. A new stamped cert will get generated.

```js
const id = ident.openCert(user).id
id.age = 33
ident.modifyProfile(user, id)
const newID = ident.openCert(user).id
t.strictEqual(newID.name, 'jim halpert')
t.strictEqual(newID.age, 33)
```

## changePass(user, oldPass, newPass, callback)

Change a user's passphrase given their old passphrase. This will re-encrypt the user's private keys using the new passhprase. It does not change any keys or any other info.

Both `user.stamp_locked` and `user.key_locked` will get re-locked using your new pass phrase.

```js
ident.changePass(user, newPass, function (err, user) {
  if (err) throw err
  // User now has a new stamp_locked and a new key_locked
})
```
