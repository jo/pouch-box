var test = require('tape')
var PouchDB = require('pouchdb')
var memdown = require('memdown')
var nacl = require('tweetnacl')

PouchDB.plugin(require('../'))

var keyPair = nacl.box.keyPair()
var permitId = 'permit/' + nacl.util.encodeBase64(keyPair.publicKey)
var dbname = 'test'

test('basics', function(t) {
  var db = new PouchDB(dbname, { db: memdown })
  var receiver

  db.box(keyPair)
    .then(function(databaseKeyPair) {
      receiver = nacl.util.encodeBase64(databaseKeyPair.publicKey)
      
      t.ok(databaseKeyPair.publicKey, 'returns database public key')
      t.ok(databaseKeyPair.secretKey, 'returns database secret key')
    })
    .then(function() {
      return db.put({ foo: 'bar' }, 'baz')
    })
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.equals(doc.foo, 'bar', 'decrypts data')
      t.ok(doc.receivers, 'has receivers')
      t.ok(receiver in doc.receivers, 'has the receiver')
    })
    .then(function() {
      db.closeBox()
    })
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.notOk(doc.foo, 'does not have foo')
      t.ok(doc.ephemeral, 'has ephemeral')
      t.ok(doc.nonce, 'has nonce')
      t.ok(doc.receivers, 'has receivers')
      t.ok(receiver in doc.receivers, 'has the receiver')
      t.ok(doc.box, 'has box')
    })
    .then(t.end)
})

test('reopen', function(t) {
  var db = new PouchDB(dbname, { db: memdown })

  db.box(keyPair)
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.equals(doc.foo, 'bar', 'decrypts data')
    })
    .then(t.end)
})

test('conflicts', function(t) {
  var db = new PouchDB(dbname, { db: memdown })
  var other = new PouchDB(dbname + '-other', { db: memdown })
  var receiver

  other.box(keyPair)
    .then(function() {
      return other.put({ foo: 'otherbar' }, 'otherbaz')
    })
    .then(function() {
      other.closeBox()
    })
    .then(function() {
      return other.replicate.to(db)
    })
    .then(function() {
      return db.box(keyPair)
    })
    .then(function(databaseKeyPair) {
      receiver = nacl.util.encodeBase64(databaseKeyPair.publicKey)
    })
    .then(function() {
      return db.get(permitId, { conflicts: true })
    })
    .then(function(doc) {
      t.notOk(doc._conflicts, 'does not have conflicts')
    })
    .then(function() {
      return db.get('otherbaz')
    })
    .then(function(doc) {
      t.equals(doc.foo, 'otherbar', 'decrypts data')
      t.ok(doc.receivers, 'has receivers')
      t.ok(receiver in doc.receivers, 'has the receiver')
    })
    .then(t.end)
    .catch(console.error.bind(console))
})
