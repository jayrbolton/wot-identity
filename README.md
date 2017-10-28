# wot-identity

Public key cryptography with libsodium on node.

This module generates some of the initial user identity stuff, such as the keypair, certification, and self-signature.

- Create public/private keypair
- Create a self-signed user identity certificate
- Create an encrypted version of the privkey for storage
- Modify the certificate (either the identity data or the expiration)

See also
- wot-validate
- wot-keyring
- wot-send

## createUser(passphrase, identityInfo, callback)

Create a new user.

`passphrase` can be any string

`identityInfo` should be an object that can be auto-converted to JSON with `JSON.stringify`. It can contain anything like name, aliases, website, email, picture, dat addresses, etc.

`callback` receives two arguments: `err` and `user`.

`user` is an object with these properties:

- `signKeys`: keys for signing. Object contains properties:
  - `pubkey`: buffer of public signing key
  - `privkey`: buffer of secret signing key. This is encrypted using the user's passphrase
- `encryptKeys`: keys for encrypting messages. Object contains properties:
  - `pubkey`: buffer of public encryption key
  - `privkey`: buffer of private encryption key. This is encrypted using the user's passphrase
- `cert`: a user certification with expiration, algorithm name, creation datetime, and identityInfo json
- `certSig`: a signature of a hash of the `cert` using the user's privkey (see `verifyUser`)
- `salt`: random salt used to generate a secret key from the user's passphrase. Needed to decrypt privkeys. Not secret.

## checkSig(user)

Verify the self-signature for the given user. This verifies that the user's identification data (stuff in their cert) was created by the user and not modified by anyone else.

The `user` object only needs to have properties for `cert`, `certSig`, and `signKeys`.

A return value of `false` means the user's cert fails validation

```
const result = checkSig(user)
```

## extendExpiration(user, ms, callback)

Extend the expiration date for the `user` certificate by `ms` milliseconds.

The `user` object must have properties for `signKeys`, `cert`.

## modifyIdentity(user, identityInfo, callback)

Modify the identity info json for a user. `identityInfo` should be an object that can be auto-converted to JSON. The cert will get re-signed.

The `user` object must have properties for `signKeys`, `cert`.
