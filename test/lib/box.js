var test = require('tape')
var nacl = require('tweetnacl')

var box = require('../../lib/box')

test('encrypt', function(t) {
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )
  var mybox = box(databaseKey)
  var doc = mybox({
    _id: 'mydoc',
    text: 'public text',
    box: {
      text: 'secret text'
    }
  })
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)

  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.equal(doc.text, 'public text', 'public text left unencrypted')
  t.ok('box' in doc, 'has box')
  t.notOk('text' in doc.box, 'does not not have text')
  t.ok('ephemeral' in doc.box, 'has ephemeral')
  t.ok('nonce' in doc.box, 'has nonce')
  t.ok('receivers' in doc.box, 'has receivers')
  t.ok(receiver in doc.box.receivers, 'has correct receiver')
  t.ok('nonce' in doc.box.receivers[receiver], 'has receiver nonce')
  t.ok('encryptedKey' in doc.box.receivers[receiver],
    'has receiver encryptedKey')
  t.ok('cipher' in doc.box, 'has cipher')

  t.end()
})

test('decrypt', function(t) {
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )
  var mybox = box(databaseKey)
  var cipherdoc = {
    _id: 'mydoc',
    box: {
      ephemeral: 'x5Qux2l/soIKFUebWq6BuevC/BE+Tn+Gl0tfHdXCtl8=',
      nonce: '3HXZwMYSwtGd0hWxlKmV3+0KBaAOqOjv',
      receivers: {
        'YU/nXYHZTEeB27cxV0AaYkFHlHlGmNNm/YsDUiw/r0s=':  {
          nonce: 'ixPfkLYEJ/f2u/MtJxqUu8H6syTIPz2H',
          encryptedKey: 'beJ/Uz0GezvYgs8+QisjhS18aCeAYCjOBatDz5dyFFFiIE4qhQT2AXUgK/1MeaMC'
        }
      },
      cipher: 'NpsNNOmg6QQqxzT/xquJ5FuQvlM/RVIkdgspx9YQNaVXGnxyzaM='
    }
  }
  var doc = mybox.open(cipherdoc)
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)

  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.ok('box' in doc, 'has box')
  t.notOk('ephemeral' in doc.box, 'does not have ephemeral')
  t.notOk('nonce' in doc.box, 'does not have nonce')
  t.ok('receivers' in doc.box, 'has receivers')
  t.ok(receiver in doc.box.receivers, 'has encrypted for receiver')
  t.ok(doc.box.receivers[receiver], 'has truish receiver')
  t.notOk('cipher' in doc.box, 'does not have cipher')
  t.equal(doc.box.text, 'secret text', 'has correct text')

  t.end()
})

test('encrypt for multiple receivers', function(t) {
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )
  var receivers = [
    nacl.box.keyPair().publicKey,
    nacl.box.keyPair().publicKey
  ]
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)
  var mybox = box(databaseKey, receivers)
  var doc = mybox({
    _id: 'mydoc',
    box: {
      text: 'secret text',
      receivers: {
        '35rhbqbIMRbeKxoiY5igtnYiQ8PLtVkjA1IuoK2ZsCc=': {
          nonce: '9e1yqUWKF3M2sBPnEhbhidKOEi9LdVhK',
          encryptedKey: 'OcollgXyW1CayVhrz9WryJBoZ1+Cu/ipJyxVXktqnMH4pIRQdKDXNERQS6R4QKty'
        }
      }
    }
  })

  t.ok('box' in doc, 'has box')
  t.ok('receivers' in doc.box, 'has receivers')
  receivers
    .concat(databaseKey.publicKey)
    .map(function(receiver) {
      return nacl.util.encodeBase64(receiver)
    })
    .concat('35rhbqbIMRbeKxoiY5igtnYiQ8PLtVkjA1IuoK2ZsCc=')
    .forEach(function(receiver) {
      t.ok(receiver in doc.box.receivers, 'has receiver')
      t.ok('nonce' in doc.box.receivers[receiver], 'has receiver nonce')
      t.ok('encryptedKey' in doc.box.receivers[receiver], 'has receiver encryptedKey')
    })
  
  t.end()
})

test('decrypt multiple receivers', function(t) {
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )
  var mybox = box(databaseKey)
  var cypher = {
    _id: 'mydoc',
    box: {
      ephemeral: 'h4mxnMOK7d7pqaBHJPsdi1xY3yfvXOftejy8EL2hslY=',
      nonce: 'kp3rrv8cWpsKF/u/T2S1HG2VOb8S0KXr',
      receivers: {
        '35rhbqbIMRbeKxoiY5igtnYiQ8PLtVkjA1IuoK2ZsCc=': {
          nonce: '9e1yqUWKF3M2sBPnEhbhidKOEi9LdVhK',
          encryptedKey: 'OcollgXyW1CayVhrz9WryJBoZ1+Cu/ipJyxVXktqnMH4pIRQdKDXNERQS6R4QKty'
        },
        'dHOQaPGtiOYhXiadgklzUrtaEbUXh5aO704r2wILAjM=': {
           nonce: '9e1yqUWKF3M2sBPnEhbhidKOEi9LdVhK',
          encryptedKey: 'OcollgXyW1CayVhrz9WryJBoZ1+Cu/ipJyxVXktqnMH4pIRQdKDXNERQS6R4QKty'
        },
        'YU/nXYHZTEeB27cxV0AaYkFHlHlGmNNm/YsDUiw/r0s=': {
          nonce: '9e1yqUWKF3M2sBPnEhbhidKOEi9LdVhK',
          encryptedKey: 'OcollgXyW1CayVhrz9WryJBoZ1+Cu/ipJyxVXktqnMH4pIRQdKDXNERQS6R4QKty'
        }
      },
      cipher: 'yZIgi6ko2Bih6ONXrDzgMIdx1AS/vWGWyUCTUdCzVVneqvkDFTw='
    }
  }
  var doc = mybox.open(cypher)
  var receivers = [
    'dHOQaPGtiOYhXiadgklzUrtaEbUXh5aO704r2wILAjM=',
    'YU/nXYHZTEeB27cxV0AaYkFHlHlGmNNm/YsDUiw/r0s='
  ]
  
  t.ok('box' in doc, 'has box')
  t.equal(doc.box.text, 'secret text', 'has correct text')
  t.ok('receivers' in doc.box, 'has receivers')
  receivers
    .concat(nacl.util.encodeBase64(databaseKey.publicKey))
    .forEach(function(receiver) {
      t.ok(receiver in doc.box.receivers, 'has receiver')
      t.ok(doc.box.receivers[receiver], 'has truish receiver')
    })

  t.end()
})

