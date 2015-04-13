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
    text: 'secret text'
  })
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)

  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.notOk('text' in doc, 'does not not have text')
  t.ok('ephemeral' in doc, 'has ephemeral')
  t.ok('nonce' in doc, 'has nonce')
  t.ok('receivers' in doc, 'has receivers')
  t.ok(receiver in doc.receivers, 'has correct receiver')
  t.ok('nonce' in doc.receivers[receiver], 'has receiver nonce')
  t.ok('encryptedKey' in doc.receivers[receiver],
    'has receiver encryptedKey')
  t.ok('box' in doc, 'has box')

  t.end()
})

test('decrypt', function(t) {
  var databaseKey = nacl.box.keyPair.fromSecretKey(
    nacl.util.decodeBase64('zScUA0d+9+fVmZNGDciQcc/VhOlUv3LVP1ZoQu3VYeI=')
  )
  var mybox = box(databaseKey)
  var cypher = {
    _id: 'mydoc',
    ephemeral: 'x5Qux2l/soIKFUebWq6BuevC/BE+Tn+Gl0tfHdXCtl8=',
    nonce: '3HXZwMYSwtGd0hWxlKmV3+0KBaAOqOjv',
    receivers: {
      'YU/nXYHZTEeB27cxV0AaYkFHlHlGmNNm/YsDUiw/r0s=':  {
        nonce: 'ixPfkLYEJ/f2u/MtJxqUu8H6syTIPz2H',
        encryptedKey: 'beJ/Uz0GezvYgs8+QisjhS18aCeAYCjOBatDz5dyFFFiIE4qhQT2AXUgK/1MeaMC'
      }
    },
    box: 'NpsNNOmg6QQqxzT/xquJ5FuQvlM/RVIkdgspx9YQNaVXGnxyzaM='
  }
  var doc = mybox.open(cypher)
  var receiver = nacl.util.encodeBase64(databaseKey.publicKey)

  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.notOk('ephemeral' in doc, 'does not have ephemeral')
  t.notOk('nonce' in doc, 'does not have nonce')
  t.ok('receivers' in doc, 'has receivers')
  t.ok(receiver in doc.receivers, 'has encrypted for receiver')
  t.ok(doc.receivers[receiver], 'has truish receiver')
  t.notOk('box' in doc, 'does not have box')
  t.equal(doc.text, 'secret text', 'has correct text')

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
    text: 'secret text',
    receivers: {
      '35rhbqbIMRbeKxoiY5igtnYiQ8PLtVkjA1IuoK2ZsCc=': {
        nonce: '9e1yqUWKF3M2sBPnEhbhidKOEi9LdVhK',
        encryptedKey: 'OcollgXyW1CayVhrz9WryJBoZ1+Cu/ipJyxVXktqnMH4pIRQdKDXNERQS6R4QKty'
      }
    }
  })

  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.notOk('text' in doc, 'does not not have text')
  t.ok('ephemeral' in doc, 'has ephemeral')
  t.ok('nonce' in doc, 'has nonce')
  t.ok('receivers' in doc, 'has receivers')
  t.ok('box' in doc, 'has box')
  receivers
    .concat(databaseKey.publicKey)
    .map(function(receiver) {
      return nacl.util.encodeBase64(receiver)
    })
    .concat('35rhbqbIMRbeKxoiY5igtnYiQ8PLtVkjA1IuoK2ZsCc=')
    .forEach(function(receiver) {
      t.ok(receiver in doc.receivers, 'has receiver')
      t.ok('nonce' in doc.receivers[receiver], 'has receiver nonce')
      t.ok('encryptedKey' in doc.receivers[receiver], 'has receiver encryptedKey')
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
    box: 'yZIgi6ko2Bih6ONXrDzgMIdx1AS/vWGWyUCTUdCzVVneqvkDFTw='
  }
  var doc = mybox.open(cypher)
  var receivers = [
    'dHOQaPGtiOYhXiadgklzUrtaEbUXh5aO704r2wILAjM=',
    'YU/nXYHZTEeB27cxV0AaYkFHlHlGmNNm/YsDUiw/r0s='
  ]
  
  t.equal(doc._id, 'mydoc', 'has correct _id')
  t.notOk('ephemeral' in doc, 'does not have ephemeral')
  t.notOk('nonce' in doc, 'does not have nonce')
  t.notOk('box' in doc, 'does not have box')
  t.equal(doc.text, 'secret text', 'has correct text')
  t.ok('receivers' in doc, 'has receivers')
  receivers
    .concat(nacl.util.encodeBase64(databaseKey.publicKey))
    .forEach(function(receiver) {
      t.ok(receiver in doc.receivers, 'has receiver')
      t.ok(doc.receivers[receiver], 'has truish receiver')
    })

  t.end()
})

