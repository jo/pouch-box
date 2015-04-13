module.exports = {
  _id: '_design/box',
  views: {
    receivers: {
      map: function(doc) {
        if (typeof doc.receivers === 'object') {
          for (var receiver in doc.receivers) {
            emit(receiver, null)
          }
        }
      }.toString(),
      reduce: '_count'
    }
  }
}
