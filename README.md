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

- `pubkey`: buffer of the user's pubkey
- `privkey`: buffer of the user's privkey
- `privkey_encrypted`: buffer of the user's encrypted privkey, using their same passphrase
- `privkey_salt`: salt used to encrypt their privkey
- `cert`: a user certification with expiration, algorithm name, creation datetime, and identityInfo json
- `certSig`: a signature of a hash of the `cert` using the user's privkey (see `verifyUser`)

## verifyUser(user, callback)

Verify the self-signature for the given user using the user's public key. This verifies that the user's identifying metadata was created by the user and not modified by anyone else.

The `user` object only needs to have properties for `cert`, `certSig`, and `pubkey` -- it does not need any privkey properties.

## extendExpiration(user, ms, callback)

Extend the expiration date for the `user` certificate by `ms` milliseconds.

The `user` object must have the `privkey` buffer property.

## modifyIdentity(user, identityInfo, callback)

Modify the identity info json for a user. `identityInfo` should be an object that can be auto-converted to JSON. 

The `user` object must have the `privkey` buffer property.
