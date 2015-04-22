var nacl = require('tweetnacl')

module.exports = function box(databaseKey, receivers) {
  receivers = receivers || []
  receivers.push(databaseKey.publicKey)
      
  var turnedOff = false
  var sender = nacl.util.encodeBase64(databaseKey.publicKey)


  // Encryption
  var box = function(doc) {
    if (turnedOff) return doc
    if (typeof doc.box !== 'object') return doc

    var key = nacl.randomBytes(nacl.secretbox.keyLength)
    var nonce = nacl.randomBytes(nacl.secretbox.nonceLength)

    var ephemeralKey = nacl.box.keyPair()

    var recs = Object.keys(doc.box.receivers || {})
      .map(function(receiver) {
        return nacl.util.decodeBase64(receiver)
      })
      .concat(receivers)
      .reduce(function(memo, publicKey) {
        var nonce = nacl.randomBytes(nacl.box.nonceLength)
        
        memo[nacl.util.encodeBase64(publicKey)] = {
          nonce: nacl.util.encodeBase64(nonce),
          encryptedKey: nacl.util.encodeBase64(nacl.box(
            key,
            nonce,
            publicKey,
            ephemeralKey.secretKey
          ))
        }

      return memo
    }, {})

    doc.box = {
      ephemeral: nacl.util.encodeBase64(ephemeralKey.publicKey),
      nonce: nacl.util.encodeBase64(nonce),
      receivers: recs,
      cipher: nacl.util.encodeBase64(nacl.secretbox(
        nacl.util.decodeUTF8(JSON.stringify(doc.box)),
        nonce,
        key
      ))
    }

    return doc
  }


  // Decryption
  box.open = function(doc) {
    if (turnedOff) return doc
    if (typeof doc.box !== 'object') return doc
    if (typeof doc.box.receivers !== 'object') return doc
    if (typeof doc.box.receivers[sender] !== 'object') return doc

    var permit = doc.box.receivers[sender]
    var key = nacl.box.open(
      nacl.util.decodeBase64(permit.encryptedKey),
      nacl.util.decodeBase64(permit.nonce),
      nacl.util.decodeBase64(doc.box.ephemeral),
      databaseKey.secretKey
    )
    if (!key) throw('Decryption error')

    var data = nacl.secretbox.open(
      nacl.util.decodeBase64(doc.box.cipher),
      nacl.util.decodeBase64(doc.box.nonce),
      key
    )
    if (!data) throw('Decryption error')

    var recs = Object.keys(doc.box.receivers)
      .reduce(function(memo, key) {
        memo[key] = true
        return memo
      }, {})

    doc.box = JSON.parse(nacl.util.encodeUTF8(data))
    doc.box.receivers = recs

    return doc
  }


  // Stop encryption / decryption and scrub databaseKey
  box.close = function() {
    turnedOff = true
    databaseKey = nacl.box.keyPair()
  }


  // Expose receivers
  box.receivers = receivers


  return box
}
