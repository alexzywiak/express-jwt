const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  // Verify username and password, call done with User
  User.findOne({ email: email })
    .then(function(user){
      if(!user){
        return done(null, false);
      }

      user.comparePassword(password)
        .then(function(isMatch){
          if(!isMatch){
            return done(null, false);
          }

          return done(null, user);
        })
        .catch(function(err){
          return done(err);
        })
    })
    .catch(function(err){
      return done(err);
    });
});

// Set up JwtStrategy Options
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  // See if user ID exists
  User.findById(payload.sub)
    .then(function(user){
      // If it does, call done with user object
      if(user){ return done(null, user); }
      
      // If it doesn't, call done without user object
      return done(null, false);
    })
    .catch(function(err){
      return done(err, false);
    });
});

// Tell Passport to use JWT Strategy
passport.use(jwtLogin);
passport.use(localLogin);