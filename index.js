var permit = require('./lib/permit')
var box = require('./lib/box')
var untouched = function(doc) { return doc }

exports.transform = require('transform-pouch').transform

exports.box = function(sessionKeyPair) {
  var db = this
  var mypermit = permit(sessionKeyPair)

  return db
    // get permit
    .get(mypermit._id)
    
    // create permit doc if not present
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
    
    // open permit
    .then(function(doc) {
      if (doc) mypermit.parse(doc)
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
