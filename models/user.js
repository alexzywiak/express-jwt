const mongoose = require('mongoose');
const Schema   = mongoose.Schema;
const bcrypt   = require('bcrypt-nodejs');
const Bluebird = require('bluebird');

const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true},
  password: String
});

userSchema.pre('save', function(next){
  const user = this;
  bcrypt.genSalt(10, function(err, salt){
    if(err){ return next(err); }

    bcrypt.hash(user.password, salt, null, function(err, hash){
      if(err){ return next(err); }

      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(testPassword){
  const user = this;
  return new Bluebird(function(resolve, reject){
    bcrypt.compare(testPassword, user.password, function(err, isMatch){
      if(err){ return reject(err) }
      return resolve(isMatch);
    });
  });
}

const model = mongoose.model('user', userSchema);

module.exports = model;