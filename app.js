//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption")
const app = express();

app.use(express.static("public"));
app.set('view engine' , 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//start mongo server for userdb with 'mongo' command and connect to our server
mongoose.connect('mongodb://localhost:27017/userDB', {
  useUnifiedTopology: true,
  useNewUrlParser: true,
});
//when user registers and submit take their info , change schema to add encryption, this comes from mongoose schema class 
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//https://www.npmjs.com/package/mongoose-encryption
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] }); //only encrypt password

const User = new mongoose.model("User", userSchema);

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

//LEVEL 1- USER NAME AND PASSWORD ONLY
//users data added to database check with robo 3t
app.post("/register", (req, res) => {
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  //During save, documents are encrypted and then signed.
  newUser.save(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets"); //if no error render secrets.ejs, it will only show secrets page, if the user is registered
    }
  });
});

//login route, check the database if we have their email and password saved inside the database
app.post("/login", function (req, res) {
  //users input
  const username = req.body.username;
  const password = req.body.password;

  //check against database, email(database) field with username(user gave)
  //problem is with password, shows as a string, for this use mongoose encryption
  // During find, documents are authenticated and then decrypted
  User.findOne({ email: username }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        if (foundUser.password === password) {  //check their password
          res.render('secrets');
        }
      }
    }
  });
});


app.listen(3000, () => {
  console.log('Server started on port 3000.');
});