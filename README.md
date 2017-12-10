# wot-identity

Public key cryptography for user identity with libsodium; part of [node-wot](https://github.com/jayrbolton/node-wot).

This library uses some different terms for key management. A user's public encryption key is their "lock", which they give out to other people. Their private encryption key is their "key", which they keep to themselves. A user's private signing key is their "thumb", which they use to sign data, and their public signing key is their "thumbprint", which they give out publicly to let people verify their signatures.

This module generates all of the initial user identity stuff, such as their keypairs and self-signed certificate. It also has basic functions for encrypting and signing data, and also for marking other users as verified.

## createUser(passphrase, profile, callback)

Create a new user. `passphrase` can be any string of at least length 7.

`profile` should be an object that can be auto-converted to JSON with `JSON.stringify`. It can contain any identifying data, such as a name.

`callback` receives two arguments: `err` and `user`.

`user` is an object with these properties:

- `thumb` - private buffer for stamping messages
- `thumb_locked` - locked thumb for storage (ouch!)
- `thumbprint` - public thumbprint for others to verify a signed message
- `key` - private key for unlocking encrypted messages
- `key_locked` - locked key for storage
- `lock` - public lock to allow anyone to encrypt a message for this user
- `cert`: a buffer of the stamped user certification

## openCert(user)

Open and validate the user's certification using their thumbprint. Will return an object of data for their cert. If the cert is invalid, either because the thumbprint doesn't match the signature or because the cert is expired, then an error will be thrown.

```
const cert = ident.openCert(user)
```

Each cert has these properties;

- `id` - a large, random, probably unique for the user
- `expiration` - date at which this certification should be considered invalid
- `lock` - the user's public lock
- `thumbprint` - the user's public thumbprint
- `profile` - the profile data for the user (in json)

## setExpiration(user, ms)

Set the expiration date for the user's certificate. The cert will get updated and resigned.

The `user` object must have properties for `signKeys`, `cert`.

## modifyProfile(user, profile, callback)

Modify the profile info for a user. `profile` should be an object that can be converted to JSON. A new stamped cert will get generated.

```js
const id = ident.openCert(user).id
id.name = 'bob'
ident.modifyProfile(user, id)
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

## signUser(signer, signee)

Verify another user's identity by signing the hash of that user's cert.

`signer` needs a `.thumb`

`signee` needs a `.cert` and a `.thumbprint`

Returns a signed hash of the `signee`'s cert

## verifySignedUser(signer, signee, signedHash)

Verify the signature that a signer has made on another user's cert

`signer` needs a `.thumbprint`

`signee` needs a `.cert` and `.thumbprint`

Throws an error if the signature is invalid

Returns the orginal signee's cert

