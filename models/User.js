var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var UserSchema = new Schema({
  username: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  url: String,
  role: String,
  banned: false,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  verifyToken: String,
  verifyTokenExpires: Date
});

module.exports = mongoose.model('User', UserSchema);
