//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption")  use md5
// const md5 = require('md5');  use bcrypt
// const bcrypt = require('bcryptjs');
// const saltRounds = 10;

// PASSPORT for cookies
const session = require('express-session');  //set up session
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
 
const app = express();

app.use(express.static("public"));
app.set('view engine' , 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//Create a session middleware with the given options
app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());   //set up passport
app.use(passport.session());      

//start mongo server for userdb with 'mongo' command and connect to our server
mongoose.connect('mongodb://localhost:27017/userDB', {
  useUnifiedTopology: true,
  useNewUrlParser: true,
});
mongoose.set("useCreateIndex", true);

//when user registers and submit take their info , change schema to add encryption, this comes from mongoose schema class 
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//https://www.npmjs.com/package/mongoose-encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] }); //only encrypt password
userSchema.plugin(passportLocalMongoose); //use to hash and salt password and save users to database

const User = new mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());
 
// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// render pages 
app.get('/', (req, res) => {
  res.render("home");
});

app.get('/login', (req, res) => {
  res.render("login");
});

app.get('/register', (req, res) => {
  res.render("register");
});

//if the user is already logged in render secrets page
app.get('/secrets', function (req, res) {
  if (req.isAuthenticated()) {
    res.render('secrets');
  } else {
    res.redirect('/login');
  }
});

//register users with passport-local-mongoose
app.post('/register', function (req, res) {
  User.register({username:req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect('/register'); //send user back to register page
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post('/login', function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //passport to log in and authenticate the user
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, function () {
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