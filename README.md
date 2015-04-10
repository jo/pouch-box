# pouch-box
Asymmetric encrypted PouchDB, powered by NaCl's curve25519-xsalsa20-poly1305.

## DARC
* Decentralized authentication
* Access control per document
* Revocation per session (account)
* Change session key (eg. when the key was derived from a password this enables
  password change)

pouch-box uses [TweetNaCl.js](https://github.com/dchest/tweetnacl-js), a port of
[TweetNaCl](http://tweetnacl.cr.yp.to/) / [NaCl](http://nacl.cr.yp.to/) to
JavaScript for modern browsers and Node.js by Dmitry Chestnykh
([@dchest](https://github.com/dchest)).

The use of this widely ported cryptography library makes it possible to
implement this encryption schema in other, possibly more secure platforms, for
example with Python and CouchDB.

**:warning: Only to play around! Not yet ready for production use.**

## Installation
pouch-box is [hosted on npm](https://www.npmjs.com/package/pouch-box).

### Node
Install via `npm install pouch-box` 

```js
var PouchDB = require('pouchdb')
PouchDB.plugin(require('pouch-box'))
```

### Browser
Use the [browserified build](./dist/pouch-box.js).

```html
<script src="pouchdb.js"></script>
<script src="pouch-box.js"></script>
```


## Usage
```js
var db = new PouchDB('mydb')

var keyPair = require('tweetnacl').box.keyPair()
// {
//   secretKey: 'smsDNnqeT40IfAwDw0+6x5WzDRYFv0492O/JW/s8tT0=',
//   publicKey: 'sAUGULAT5q2g6gzNMuBX1tkY/FsnoiLA/tv2XmmU2Dg='
// }

db.box(keyPair)
  .then(function() {
    // db is encrypted now :P
  })

// and later...
db.closeBox()
```

## Details
pouch-box uses three keys: session keys, database keys and document keys:

### Session Key
The session keypair is a `Curve25519` keypair from NaCl `crypto_box`. Session
keys are not stored in the database, but a permit is created which allows the
owner of the session key to decrypt the database key and grant access.

An session keypair looks like this, when encoded as base64:
```json
{
  "secretKey": "smsDNnqeT40IfAwDw0+6x5WzDRYFv0492O/JW/s8tT0=",
  "publicKey": "sAUGULAT5q2g6gzNMuBX1tkY/FsnoiLA/tv2XmmU2Dg="
}
```

The keypair above can be created in node with
[tweetnacl](https://github.com/dchest/tweetnacl-js):
```js
var nacl = require('tweetnacl')

var sessionKeyPair = nacl.box.keyPair()

{
  secretKey: nacl.util.encodeBase64(sessionKeyPair.secretKey),
  publicKey: nacl.util.encodeBase64(sessionKeyPair.publicKey)
}
```


### Database Key
A database can have one or more database keys. The private database key is
stored encrypted in permit documents.

```json
{
  "secretKey": "LCvM/keRcO00AguI5aBX+tY0UfIb7n5w294JJZ2i1XU=",
  "publicKey": "2XiwPX1U6pKPitmhyeubV9g4YYxtIxNfMNE6B5keEmg="
}
```
The keys are both 32 bytes long. They are based on Curve25519 and created with
the [NaCl crypto_box](http://nacl.cr.yp.to/box.html) `crypto_box_keypair`
function.

The keypair above was created similar to session key generation by the following
statements:
```js
var nacl = require('tweetnacl')

var databaseKeyPair = nacl.box.keyPair()

{
  secretKey: nacl.util.encodeBase64(databaseKeyPair.secretKey),
  publicKey: nacl.util.encodeBase64(databaseKeyPair.publicKey)
}
```


### Permit: `permit/<permit-id>`
A permit contains the database secret key, encrypted with the public session
key. Decoupling of session and database keys allows the account holder to change
its keys and also enables the use of different public key algorithms for session
keys.

The schema of the permit varies between the chosen algorithms. By now only
`curve25519-xsalsa20-poly1305` is supported. This may change in the future.

The permit id is the base64 encoded public session key, prefixed with
`permit/`.

In order to create the database permit we

1. Create an ephemeral key pair
2. Create a nonce
3. Encrypt the database secret key with nonce, public session key and ephemeral
secret key

```json
{
  "_id": "permit/sAUGULAT5q2g6gzNMuBX1tkY/FsnoiLA/tv2XmmU2Dg=",
  "type": "curve25519-xsalsa20-poly1305",
  "createdAt": "2015-03-18T01:29:46.764Z",
  "ephemeral": "RxYOHMWUri/8+aVUDodcocOhTBakV5BckIU9kdeFwSo=",
  "nonce": "Le1AvMAvjkVy3mn1knnmovY36lYk028K",
  "encryptedKey": "7aX5QPyU7OABMFD6YZJF8akTqiNnP4LN9CetpsW/37LgRdl5DPuPtoUiahCMGbCq"
}
```

```js
var nacl = require('tweetnacl')

var sessionKeyPair = nacl.box.keyPair.fromSecretKey(
  nacl.util.decodeBase64('smsDNnqeT40IfAwDw0+6x5WzDRYFv0492O/JW/s8tT0=')
)
var databaseKeyPair = nacl.box.keyPair.fromSecretKey(
  nacl.util.decodeBase64('LCvM/keRcO00AguI5aBX+tY0UfIb7n5w294JJZ2i1XU=')
)
var permitEphemeralKeyPair = nacl.box.keyPair()
var permitNonce = nacl.randomBytes(nacl.box.nonceLength)

{
  _id: 'permit/' + nacl.util.encodeBase64(sessionKeyPair.publicKey),
  type: 'curve25519-xsalsa20-poly1305',
  createdAt: new Date(),
  ephemeral: nacl.util.encodeBase64(permitEphemeralKeyPair.publicKey),
  nonce: nacl.util.encodeBase64(permitNonce),
  encryptedKey: nacl.util.encodeBase64(nacl.box(
    databaseKeyPair.secretKey,
    permitNonce,
    sessionKeyPair.publicKey,
    permitEphemeralKeyPair.secretKey
  ))
}
```


### Document
Each document is encrypted with its own key. For each database key which was
given access to the document a permit is included in the meta document. This
empowers the owner to grant access to other accounts on a per document basis.

Each document has its own key which is used together with [Nacl secret-key
authenticated encryption](http://nacl.cr.yp.to/secretbox.html). The key consists
of 32 random bytes.

In order to create the doc permit we
1. Create an ephemeral key pair
2. Create a nonce
3. Encrypt the document key with nonce, public database key and ephemeral secret key

```json
{
  "_id" : "a069f1041735910cf8f613d20000116b",
  "ephemeral" : "PuiUBvQY+7ZFPXXUQ1N2eNE9tgPgIkT1uWj9rpShwXY=",
  "nonce": "zGDblW4Ov8sMKG3YcV/BISueH+REtDr3",
  "receivers": {
    "2XiwPX1U6pKPitmhyeubV9g4YYxtIxNfMNE6B5keEmg=": {
      "nonce": "pSquTTn+/I7REorstK6hSYeKizajtu65",
      "encryptedKey": "GXEfX7V3IwA0izAAJ3HIRCzxDFIUfxMq82QO49ITwKzbi+S+5TanJ/9ubmxOUyBh"
    }
  },
  "box": "D9xRZl+/k0gvdBx33CGKaGfLTH731T6jhkMXfh9GfVxETGmTcpzqSJNQ42GPzsafycpdSd7ZTTWBO2vXu06dCha/X8P8C+F6Po+LeerJhKgG"
}
```

```js
var nacl = require('tweetnacl')
var pouchdb = require('pouchdb')

var databaseKeyPair = nacl.box.keyPair.fromSecretKey(
  nacl.util.decodeBase64('LCvM/keRcO00AguI5aBX+tY0UfIb7n5w294JJZ2i1XU=')
)
var ephemeralKeyPair = nacl.box.keyPair()
var ephemeralNonce = nacl.randomBytes(nacl.box.nonceLength)
var key = nacl.randomBytes(nacl.secretbox.keyLength)
var nonce = nacl.randomBytes(nacl.secretbox.nonceLength)

{
  _id: pouchdb.utils.uuid(32),
  ephemeral: nacl.util.encodeBase64(ephemeralKeyPair.publicKey),
  nonce: nacl.util.encodeBase64(ephemeralNonce),
  receivers: {
    [nacl.util.encodeBase64(databaseKeyPair.publicKey)]: {
      nonce: nacl.util.encodeBase64(nonce),
      encryptedKey: nacl.util.encodeBase64(nacl.box(
        key,
        nonce,
        databaseKeyPair.publicKey,
        ephemeralKeyPair.secretKey
      ))
    }
  },
  box: nacl.util.encodeBase64(nacl.secretbox(
    nacl.util.decodeUTF8(JSON.stringify({
      text: 'A secure text.',
      createdAt: new Date()
    )),
    nonce,
    key
  ))
}
```

## Testing
```sh
npm test
```
