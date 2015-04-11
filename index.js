var permit = require('./lib/permit')
var box = require('./lib/box')
var nacl = require('tweetnacl')
var ddoc = require('./lib/ddoc')
var untouched = function(doc) { return doc }

exports.transform = require('transform-pouch').transform

exports.box = function(sessionKeyPair) {
  var db = this
  var mypermit = permit(sessionKeyPair)


  return db
    // setup design document
    .get(ddoc._id)
    .catch(function(err) {
      if (err.status === 404) {
        return db.put(ddoc)
      }
      
      return err
    })

    
    // setup permit
    .then(function() {
      return db.get(mypermit._id, { conflicts: true })
    })
    .then(function(doc) {
      mypermit.parse(doc)
    })
    .catch(function(err) {
      if (err.status === 404) {
        mypermit.build()
        var doc = mypermit.toJSON()

        return db.put(doc)
          .then(function(resp) {
            doc._rev = resp.rev
          })
      }
      
      return err
    })


    // handle permit conflicts
    .then(function() {
      // if conflicts, resolve and use the new permit
      if (mypermit._conflicts) {
        var permits
        
        return db
          // fetch other conflicting revisions
          .get(mypermit._id, {
            open_revs: mypermit._conflicts
          })
          // parse other conflicting revisions
          .then(function(conflicts) {
            permits = conflicts
              .map(function(conflict) {
                var p = permit(sessionKeyPair)
                p.parse(conflict.ok)
                return p
              })
              .concat(mypermit)
          })
          // open all permits
          .then(function() {
            return permits.map(function(p) {
              return p.open()
            })
          })
          // calculate receiver keys
          .then(function(databaseKeys) {
            return databaseKeys.map(function(key) {
              return nacl.util.encodeBase64(key.publicKey)
            })
          })
          // query receiver counts
          .then(function(receivers) {
            return db.query('permit/receivers', {
              keys: receivers,
              group: true
            })
          })
          // remember receiver counts
          .then(function(counts) {
            counts.rows.forEach(function(row, i) {
              permits[i].count = row.value
            })
          })
          // sort by receiver counts
          .then(function() {
            permits.sort(function(a, b) {
              if (a.count === b.count) return 0

              return a.count > b.count ? 1 : -1
            })
          })
          // convert permits
          .then(function() {
            var choosenPermit = permits.pop()
            var choosenDatabaseKey = choosenPermit.open()
            var choosenBox = box(choosenDatabaseKey)

            return Promise
              .all(permits.map(function(p) {
                var key = p.open()
                var receiver = nacl.util.encodeBase64(key.publicKey)

                if (p.count === 0) return db.remove(p._id, p._rev)

                return db
                  // get docs for receiver
                  .query('permit/receivers', {
                    reduce: false,
                    key: receiver,
                    include_docs: true
                  })
                  // decrypt docs
                  .then(function(view) {
                    var pbox = box(key)
                    return view.rows.map(function(row) {
                      return pbox.open(row.doc)
                    })
                  })
                  // encrypt docs with chosen permit
                  .then(function(docs) {
                    return docs.map(function(doc) {
                      return choosenBox(doc)
                    })
                  })
                  // save docs
                  .then(function(docs) {
                    return db.bulkDocs(docs)
                  })
                  // delete permit
                  .then(function(resps) {
                    var failures = resps.filter(function(resp) {
                      return !resp.ok
                    })
                    if (failures.length === 0) return db.remove(p._id, p._rev)
                  })
              }))
              .then(function() {
                delete choosenPermit._conflicts
              })
              // update current permit with choosen permit
              .then(function() {
                if (mypermit._rev !== choosenPermit._rev) {
                  mypermit.parse(choosenPermit.toJSON())
                }
              })
          })
      }
    })
    
    
    // open permit
    .then(function() {
      return mypermit.open()
    })
   
    
    // setup transform pouch
    .then(function(databaseKey) {
      var mybox = box(databaseKey)

      db.transform({
        incoming: mybox,
        outgoing: mybox.open
      })

      db.closeBox = mybox.close

      return databaseKey
    })
}

if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(module.exports)
}
