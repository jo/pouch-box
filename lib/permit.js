var nacl = require('tweetnacl')

module.exports = function permit(sessionKey, databaseKey) {
  var permit = {
    _id: 'permit/' + nacl.util.encodeBase64(sessionKey.publicKey),
    type: 'curve25519-xsalsa20-poly1305',
    sessionKey: sessionKey,
    databaseKey: databaseKey || nacl.box.keyPair()
  }

  permit.toJSON = function() {
    return {
      _id: permit._id,
      _rev: permit._rev,
      type: permit.type,
      nonce: nacl.util.encodeBase64(permit.nonce),
      ephemeral: nacl.util.encodeBase64(permit.ephemeral),
      encryptedKey: nacl.util.encodeBase64(permit.encryptedKey)
    }
  }

  permit.build = function() {
    var nonce = nacl.randomBytes(nacl.box.nonceLength)
    var ephemeralKey = nacl.box.keyPair()

    permit.nonce = nonce
    permit.ephemeral = ephemeralKey.publicKey
    permit.encryptedKey = nacl.box(
      permit.databaseKey.secretKey,
      nonce,
      sessionKey.publicKey,
      ephemeralKey.secretKey
    )

    return permit
  }

  permit.parse = function(json) {
    permit.type = json.type
    permit.nonce = nacl.util.decodeBase64(json.nonce)
    permit.ephemeral = nacl.util.decodeBase64(json.ephemeral)
    permit.encryptedKey = nacl.util.decodeBase64(json.encryptedKey)

    var secretKey = nacl.box.open(
      permit.encryptedKey,
      permit.nonce,
      permit.ephemeral,
      sessionKey.secretKey
    )
    permit.databaseKey = nacl.box.keyPair.fromSecretKey(secretKey)
    
    permit._conflicts = json._conflicts
    permit._rev = json._rev

    return permit
  }

  permit.receiver = function() {
    return nacl.util.encodeBase64(permit.databaseKey.publicKey)
  }

  return permit
}
