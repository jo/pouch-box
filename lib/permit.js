var nacl = require('tweetnacl')

module.exports = function permit(sessionKey) {
  var permit = {
    _id: 'permit/' + nacl.util.encodeBase64(sessionKey.publicKey),
    type: 'curve25519-xsalsa20-poly1305'
  }

  permit.toJSON = function() {
    return {
      _id: permit._id,
      type: permit.type,
      nonce: nacl.util.encodeBase64(permit.nonce),
      ephemeral: nacl.util.encodeBase64(permit.ephemeral),
      encryptedKey: nacl.util.encodeBase64(permit.encryptedKey)
    }
  }

  permit.build = function(databaseKey) {
    databaseKey = databaseKey || nacl.box.keyPair()

    var nonce = nacl.randomBytes(nacl.box.nonceLength)
    var ephemeralKey = nacl.box.keyPair()

    permit.nonce = nonce
    permit.ephemeral = ephemeralKey.publicKey
    permit.encryptedKey = nacl.box(
      databaseKey.secretKey,
      nonce,
      sessionKey.publicKey,
      ephemeralKey.secretKey
    )

    return databaseKey
  }

  permit.parse = function(json) {
    permit.type = json.type
    permit.nonce = nacl.util.decodeBase64(json.nonce)
    permit.ephemeral = nacl.util.decodeBase64(json.ephemeral)
    permit.encryptedKey = nacl.util.decodeBase64(json.encryptedKey)
  }

  permit.open = function() {
    var secretKey = nacl.box.open(
      permit.encryptedKey,
      permit.nonce,
      permit.ephemeral,
      sessionKey.secretKey
    )

    return nacl.box.keyPair.fromSecretKey(secretKey)
  }
  
  return permit
}
