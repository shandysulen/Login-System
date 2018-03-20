const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

var router = express.Router();

var expressValidator = require('express-validator');
router.use(expressValidator())

var User = require('../models/User.model.js');

// Register
router.get('/register', (req, res) => {
  res.render('register');
});

// Login
router.get('/login', (req, res) => {
  res.render('login');
});

// Register User
router.post('/register', (req, res) => {
  var name = req.body.name;
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var confirm = req.body.confirm;

  // Validation
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'Name is required').notEmpty();
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('username', 'Username is required').notEmpty();
  req.checkBody('password', 'Password is required').notEmpty();
  req.checkBody('confirm', 'Passwords do not match').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    console.log("errors");
    res.render('register', {
      errors: errors
    });
  } else {
    var newUser = new User({
      name: name,
      username: username,
      email: email,
      password: password
    });

    User.createUser(newUser, function(err, user) {
          if(err) throw err;
          console.log(user);
    });

    req.flash('success_msg', 'You are registered and can now login');
    res.redirect('/users/login');
  }
});

passport.use(new LocalStrategy(
  function(username, password, done) {
      User.getUserByUsername(username, (err, user) => {
        if (err) throw err;
        if(!user){
          return done(null, false, {message: 'Unknown User'});
        }
        User.comparePassword(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch){
            return done(null, user);
          } else {
            return done(null, false, {message: 'Invalid password'});
          }
        });
      });
}));

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login', failureFlash: true}),
  function(req, res) {
    // If this function gets called, authentication was successful.
    // `req.user` contains the authenticated user.
    res.redirect('/');
  });

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
