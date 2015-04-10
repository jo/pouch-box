var test = require('tape')
var PouchDB = require('pouchdb')
var memdown = require('memdown')
var nacl = require('tweetnacl')

PouchDB.plugin(require('../'))

var keyPair = nacl.box.keyPair()
var dbname = 'test'

test('basics', function(t) {
  var db = new PouchDB(dbname, { db: memdown })

  db.box(keyPair)
    .then(function() {
      return db.put({ foo: 'bar' }, 'baz')
    })
    .then(function() {
      return db.get('baz')
    })
    .then(function(doc) {
      t.equals(doc.foo, 'bar', 'decrypts data')
      t.ok(doc.receivers, 'has receivers')
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
