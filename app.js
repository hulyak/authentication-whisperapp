//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require("mongoose-encryption")  use md5
// const md5 = require('md5');  use bcrypt
// const bcrypt = require('bcryptjs');
// const saltRounds = 10;

// PASSPORT for cookies
const session = require('express-session'); //set up session
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

//http://www.passportjs.org/packages/passport-google-oauth20/
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const strategy = require('passport-facebook');
const FacebookStrategy = strategy.Strategy;
const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

//Create a session middleware with the given options
app.use(
  session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize()); //set up passport
app.use(passport.session());

//start mongo server for userdb with 'mongo' command and connect to our server
mongoose.connect('mongodb://localhost:27017/userDB', {
  useUnifiedTopology: true,
  useNewUrlParser: true,
});
mongoose.set('useCreateIndex', true);

//when user registers and submit take their info , change schema to add encryption, this comes from mongoose schema class
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String, 
  secret: String,
  facebookId:String
});

//https://www.npmjs.com/package/mongoose-encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] }); //only encrypt password
userSchema.plugin(passportLocalMongoose); //use to hash and salt password and save users to database
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support,
//passport local mongoose doesn't work for google auth
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile)
      User.findOrCreate({ googleId: profile.id }, function(err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["email", "name"]
    },
    function (accessToken, refreshToken, profile, done) {
      console.log(profile);
      User.findOrCreate({ facebookId: profile.id }, function(err, user) {
        return done(err, user);
      });
    }
  )
);

// render pages
app.get('/', (req, res) => {
  res.render('home');
});

//authenticate user with Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

// redirect user to website
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/fb/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
   function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

//de-authenticate the user
app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

//if the user is already logged in render secrets page
app.get('/secrets', function(req, res) {
  if (req.isAuthenticated()) {
    res.render('secrets');
  } else {
    res.redirect('/login');
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  //find the current user and save the secret into their file, passport saves user info inside req.user
  //find the user by their id
  console.log(req.user);
  User.findById(req.user.id, function (err, foundUser){
    if(err) {
      console.log(err);
    }else{
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets"); //save secret to database and show to user
        });
      }
    }
  });
});
//register users with passport-local-mongoose
app.post('/register', function(req, res) {
  User.register({ username: req.body.username }, req.body.password, function(
    err,
    user
  ) {
    if (err) {
      console.log(err);
      res.redirect('/register'); //send user back to register page
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('/secrets');
      });
    }
  });
});

app.post('/login', function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  //passport to log in and authenticate the user
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('/secrets');
      });
    }
  });
});

//LEVEL 1- USER NAME AND PASSWORD ONLY
//users data added to database check with robo-3t
// app.post("/register", (req, res) => {

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         const newUser = new User({
//          email: req.body.username,
//         password: md5(req.body.password) //irreversible hash
//           password: hash  //bcrypt + 10 rounds of salting
//         });

//       During save, documents are encrypted and then signed(with mongoose encryption)
//       newUser.save(function (err) {
//         if (err) {
//           console.log(err);
//         } else {
//           res.render("secrets"); //if no error render secrets.ejs, it will only show secrets page, if the user is registered
//        }
//     });
//   });
// });

//login route, check the database if we have their email and password saved inside the database
// app.post("/login", function (req, res) {
//users input
//   const username = req.body.username;
// const password = md5(req.body.password);
//   const password = req.body.password;

//check against database, email(database) field with username(user gave)
//problem is with password, shows as a string, for this use mongoose encryption
// During find, documents are authenticated and then decrypted
//   User.findOne({ email: username }, function (err, foundUser) {
//     if (err) {
//       console.log(err);
//     } else {
//       if (foundUser) {
// if (foundUser.password === password) {  //check their password
//compare passwords
//         bcrypt.compare(password, foundUser.password, function (err, result) {
//           if (result === true) {
//             res.render('secrets');
//           }
//         });
//       }
//     }
//   });
// });

app.listen(3000, () => {
  console.log('Server started on port 3000.');
});
