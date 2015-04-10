var test = require('tape')
var nacl = require('tweetnacl')

var permit = require('../../lib/permit')

test('setup', function(t) {
  var publicKey = 'liofnczKPhM8awUO4/nzujz95StpmxZtZ/wseIlyxDM='
  var key = {
    publicKey: nacl.util.decodeBase64(publicKey)
  }

  var doc = permit(key)

  t.equal(doc._id, 'permit/' + publicKey,
    '_id is base64 encoded key, prepended with `permit/`')
  t.equal(doc.type, 'curve25519-xsalsa20-poly1305',
    'type is `curve25519-xsalsa20-poly1305`')
  
  t.end()
})

test('build', function(t) {
  var sessionKey = nacl.box.keyPair()
  var databaseKey = nacl.box.keyPair()

  var doc = permit(sessionKey)
  doc.build(databaseKey)

  t.equal(doc.nonce.length, nacl.box.nonceLength,
    'nonce has correct length')
  t.equal(doc.ephemeral.length, nacl.box.publicKeyLength,
    'ephemeral has correct length')
  
  t.end()
})

test('toJSON', function(t) {
  var sessionKey = nacl.box.keyPair()
  var databaseKey = nacl.box.keyPair()

  var doc = permit(sessionKey)
  doc.build(databaseKey)
  
  var json = doc.toJSON()

  t.equal(json.nonce, nacl.util.encodeBase64(doc.nonce),
    'encodes nonce')
  t.equal(json.ephemeral, nacl.util.encodeBase64(doc.ephemeral),
    'encodes ephemeral')
  t.equal(json.encryptedKey, nacl.util.encodeBase64(doc.encryptedKey),
    'encodes encryptedKey')

  t.end()
})

test('open', function(t) {
  var json = {
    type: 'curve25519-xsalsa20-poly1305',
    nonce: 'am250mPbUgzEcZh3tv4ENykhq9jeRFpe',
    ephemeral: 'DWI7ilYuM+ve2ET+52UyQhLO4RgVEuXo3Z183HxLygM=',
    encryptedKey: 'CRv7P3GjRMbP3FnnTedMGXBs+UddD0iDk8YWXytcZVU90+bLxOJuUOePvzmsdLrE'
  }
  var sessionKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('o32s/hTzpwzA5SxOI6sDMUyOnBGeocsU4hkBGF580tw=')
  )
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )

  var doc = permit(sessionKey)
  doc.parse(json)

  t.deepEqual(doc.open(), databaseKey, 'decrypts permit')

  t.end()
})
