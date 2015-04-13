var nacl = require('tweetnacl')
var pick = require('lodash/object/pick')
var omit = require('lodash/object/omit')
var assign = require('lodash/object/assign')

function underscoreProperties(_, key) {
  return key[0] === '_'
}

module.exports = function box(databaseKey, receivers) {
  receivers = receivers || []
  receivers.push(databaseKey.publicKey)
      
  var turnedOff = false
  var sender = nacl.util.encodeBase64(databaseKey.publicKey)


  // Encryption
  var box = function(doc) {
    if (turnedOff) return doc
    if (doc._id.match(/^permit\//)) return doc

    var key = nacl.randomBytes(nacl.secretbox.keyLength)
    var nonce = nacl.randomBytes(nacl.secretbox.nonceLength)

    var ephemeralKey = nacl.box.keyPair()

    var recs = Object.keys(doc.receivers || {})
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

    var box = nacl.util.encodeBase64(nacl.secretbox(
      nacl.util.decodeUTF8(JSON.stringify(omit(doc, underscoreProperties))),
      nonce,
      key
    ))

    return assign({
        ephemeral: nacl.util.encodeBase64(ephemeralKey.publicKey),
        nonce: nacl.util.encodeBase64(nonce),
        receivers: recs,
        box: box
      },
      pick(doc, underscoreProperties))
  }


  // Decryption
  box.open = function(doc) {
    if (turnedOff) return doc
    if (doc._id.match(/^permit\//)) return doc
    if (doc._id.match(/^_design\//)) return doc
    if (!(sender in doc.receivers)) return doc

    var permit = doc.receivers[sender]
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

    var recs = Object.keys(doc.receivers)
      .reduce(function(memo, key) {
        memo[key] = true
        return memo
      }, {})

    return assign(JSON.parse(nacl.util.encodeUTF8(data)),
      pick(doc, underscoreProperties), {
        receivers: recs
      })
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
