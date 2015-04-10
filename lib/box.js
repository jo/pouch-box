var nacl = require('tweetnacl')

module.exports = function box(databaseKey) {
  var turnedOff = false
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)

  var box = function(doc) {
    if (turnedOff) return doc
    if (doc._id.match(/^permit\//)) return doc

    var key = nacl.randomBytes(nacl.secretbox.keyLength)
    var nonce = nacl.randomBytes(nacl.secretbox.nonceLength)

    var ephemeralKey = nacl.box.keyPair()
    var ephemeralNonce = nacl.randomBytes(nacl.box.nonceLength)

    var receivers = {}
    receivers[receiver] = {
      nonce: nacl.util.encodeBase64(ephemeralNonce),
      encryptedKey: nacl.util.encodeBase64(nacl.box(
        key,
        ephemeralNonce,
        databaseKey.publicKey,
        ephemeralKey.secretKey
      ))
    }

    var cypherDoc = {}
    var toEncrypt = {}
    for (var property in doc) {
      if (property[0] === '_') {
        cypherDoc[property] = doc[property]
      } else {
        toEncrypt[property] = doc[property]
      }
    }
    
    cypherDoc.ephemeral = nacl.util.encodeBase64(ephemeralKey.publicKey)
    cypherDoc.nonce = nacl.util.encodeBase64(nonce)
    cypherDoc.receivers = receivers,

    cypherDoc.box = nacl.util.encodeBase64(nacl.secretbox(
      nacl.util.decodeUTF8(JSON.stringify(toEncrypt)),
      nonce,
      key
    ))

    return cypherDoc
  }

  box.open = function(doc) {
    if (turnedOff) return doc
    if (doc._id.match(/^permit\//)) return doc
    if (!(receiver in doc.receivers)) return doc

    var permit = doc.receivers[receiver]
    var key = nacl.box.open(
      nacl.util.decodeBase64(permit.encryptedKey),
      nacl.util.decodeBase64(permit.nonce),
      nacl.util.decodeBase64(doc.ephemeral),
      databaseKey.secretKey
    )
    if (!key) throw('Decryption error')

    var data = nacl.secretbox.open(
      nacl.util.decodeBase64(doc.box),
      nacl.util.decodeBase64(doc.nonce),
      key
    )
    if (!data) throw('Decryption error')

    var json = JSON.parse(nacl.util.encodeUTF8(data))
    
    for (var property in doc) {
      if (property[0] === '_') {
        json[property] = doc[property]
      }
    }
    
    json.receivers = {}
    json.receivers[receiver] = true
    
    return json
  }

  box.close = function() {
    turnedOff = true
    databaseKey = nacl.box.keyPair()
  }

  return box
}
