var Promise = require('pouchdb-promise')

var permit = require('./lib/permit')
var box = require('./lib/box')
var ddoc = require('./lib/ddoc')


exports.transform = require('transform-pouch').transform

exports.box = function(sessionKeyPair, receivers) {
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
            mypermit._rev = resp.rev
          })
      }
      
      return err
    })


    // handle permit conflicts
    .then(function() {
      // if conflicts, resolve and use the new permit
      if (mypermit._conflicts) {
        return db
          // fetch other conflicting revisions
          .get(mypermit._id, {
            open_revs: mypermit._conflicts
          })
          // parse other conflicting revisions
          .then(function(conflicts) {
            return conflicts
              .map(function(conflict) {
                return permit(sessionKeyPair)
                  .parse(conflict.ok)
              })
              .concat(mypermit)
          })
          // query receiver counts
          .then(function(permits) {
            return db
              .query('box/receivers', {
                keys: permits.map(function(p) {
                  return p.receiver()
                }),
                group: true
              })
              // remember receiver counts
              .then(function(counts) {
                counts.rows.forEach(function(row, i) {
                  permits[i].count = row.value
                })

                // sort by receiver counts
                return permits.sort(function(a, b) {
                  if (a.count === b.count) return 0

                  return a.count > b.count ? 1 : -1
                })
              })
          })
          // convert permits
          .then(function(permits) {
            var choosenPermit = permits.pop()
            var choosenBox = box(choosenPermit.databaseKey)

            return Promise
              .all(permits.map(function(p) {
                if (p.count === 0) return db.remove(p._id, p._rev)

                return db
                  // get docs for receiver
                  .query('box/receivers', {
                    reduce: false,
                    key: p.receiver(),
                    include_docs: true
                  })
                  // decrypt docs
                  .then(function(view) {
                    var pbox = box(p.databaseKey)
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
    
    
    // setup transform pouch
    .then(function() {
      var mybox = box(mypermit.databaseKey, receivers)

      db.transform({
        incoming: mybox,
        outgoing: mybox.open
      })

      db.closeBox = mybox.close

      return mypermit
    })
}

if (typeof window !== 'undefined' && window.PouchDB) {
  window.nacl = require('tweetnacl')
  window.PouchDB.plugin(module.exports)
}
