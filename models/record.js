var mongoose = require('mongoose');

var Schema = mongoose.Schema;

module.exports = mongoose.model(
  'Record', new Schema({
      userId : {type: Schema.ObjectId, ref: 'User'},
      role: String,
      className: String,
      date: Date
  })
);
