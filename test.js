var test = require('tape')
var PouchDB = require('pouchdb')
var memdown = require('memdown')
var nacl = require('tweetnacl')

PouchDB.plugin(require('./'))

var keyPair = nacl.box.keyPair()
var permitId = 'permit/' + nacl.util.encodeBase64(keyPair.publicKey)
var dbname = 'test'

test('basics', function(t) {
  var db = new PouchDB(dbname, { db: memdown })
  var receiver

  db.box(keyPair)
    .then(function(permit) {
      receiver = permit.receiver()
      
      t.ok(permit.databaseKey.publicKey, 'returns database public key')
      t.ok(permit.databaseKey.secretKey, 'returns database secret key')
    })
    .then(function() {
      return db.put({ box: { foo: 'bar' } }, 'baz')
    })
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.equals(doc.box.foo, 'bar', 'decrypts data')
      t.ok(doc.box.receivers, 'has receivers')
      t.ok(receiver in doc.box.receivers, 'has the receiver')
    })
    .then(function() {
      db.closeBox()
    })
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.notOk(doc.box.foo, 'does not have foo')
      t.ok(doc.box.receivers, 'has receivers')
      t.ok(receiver in doc.box.receivers, 'has the receiver')
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
      t.equals(doc.box.foo, 'bar', 'decrypts data')
    })
    .then(t.end)
})

test('share', function(t) {
  var alice = new PouchDB(dbname + '-share', { db: memdown })
  var bob = new PouchDB(dbname + '-share', { db: memdown })
  
  var aliceKey = nacl.box.keyPair()
  var bobKey = nacl.box.keyPair()

  alice.box(aliceKey)
    .then(function(alicePermit) {
      return bob.box(bobKey, [alicePermit.databaseKey.publicKey])
        .then(function() {
          return bob.put({ box: { foo: 'bar' } }, 'baz')
        })
        .then(function(asd) {
          return alice.get('baz')
        })
        .then(function(doc) {
          t.equals(doc.box.foo, 'bar', 'decrypts data')
        })
        .then(t.end)
    })
})

test('conflicts', function(t) {
  var db = new PouchDB(dbname, { db: memdown })
  var other = new PouchDB(dbname + '-other', { db: memdown })
  var receiver

  other.box(keyPair)
    .then(function() {
      return other.put({ box: { foo: 'otherbar' } }, 'otherbaz')
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
    .then(function(permit) {
      receiver = permit.receiver()
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
      t.equals(doc.box.foo, 'otherbar', 'decrypts data')
      t.ok(doc.box.receivers, 'has receivers')
      t.ok(receiver in doc.box.receivers, 'has the receiver')
    })
    .then(t.end)
})
