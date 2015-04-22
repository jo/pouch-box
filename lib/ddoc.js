module.exports = {
  _id: '_design/box',
  views: {
    receivers: {
      map: function(doc) {
        if (typeof doc.box !== 'object') return
        if (typeof doc.box.receivers !== 'object') return

        for (var receiver in doc.box.receivers) {
          emit(receiver, null)
        }
      }.toString(),
      reduce: '_count'
    }
  }
}
