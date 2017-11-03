# wot-identity

Public key cryptography for user identity with libsodium on node.

This module generates some of the initial user identity stuff, such as the keypair, certification, and self-signature.

- Create public/private keypairs (separate pairs for signing and for encryption)
- Create a self-signed user identity certificate
- Create an encrypted version of the privkey for storage
- Modify the certificate (either the identity data or the expiration)
- Update a user's passhprase

See also
- [wot-send](https://github.com/jayrbolton/wot-send) -- send messages between users
- wot-validate -- validate user identity and assign trust
- wot-keyring -- save a collection of users and their metadata
- wot-serialize -- save all your stuff to disk in a standard way

## createUser(passphrase, identityInfo, callback)

Create a new user.

`passphrase` can be any string

`identityInfo` should be an object that can be auto-converted to JSON with `JSON.stringify`. It can contain anything like name, aliases, website, email, dat addresses, etc.

`callback` receives two arguments: `err` and `user`.

`user` is an object with these properties:

- `signKeys`: keys for signing. Object contains properties:
  - `pubkey`: buffer of public signing key
  - `privkey`: buffer of secret signing key. This is encrypted using the user's passphrase
- `encryptKeys`: keys for encrypting messages. Object contains properties:
  - `pubkey`: buffer of public encryption key
  - `privkey`: buffer of private encryption key. This is encrypted using the user's passphrase
- `cert`: a buffer of the user certification with self signature, expiration, algorithm name, creation datetime, pubkeys, and identity info
- `salt`: random salt used to generate a secret key from the user's passphrase. Not secret

## openCert(user)

Open and validate the user's certification using their signing public key. Will return an object of data for their cert. If the cert is invalid, will throw an error.

```
const cert = openCert(user)
t.strictEqual(cert.id.name, userName)
t.strictEqual(cert.encryptPub.length, 64)
t.strictEqual(cert.signPub.length, 64)
t.strictEqual(cert.algo, 'Ed25519')
t.assert(cert.expiration > Date.now())
```

## setExpiration(user, ms)

Set the expiration date for the user's certificate. The cert will get updated and resigned.

The `user` object must have properties for `signKeys`, `cert`.

## modifyIdentity(user, identityInfo, callback)

Modify the identity info json for a user. `identityInfo` should be an object that can be auto-converted to JSON. The cert will get re-signed.

The `user` object must have properties for `signKeys`, `cert`.

## changePass(user, oldPass, newPass, callback)

Change a user's passphrase given their old passphrase. This will re-encrypt the user's private keys using the new passhprase. It does not change any keys or any other info.
