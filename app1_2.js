
//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy= require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const InternalOAuthError = require('passport-oauth').InternalOAuthError;


const app = express();

app.use(express.static("public"));
app.set("view engine", 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    // useCreateIndex: true,
    // useFindAndModify: false
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user,done){
    done(null,user.id);
});
passport.deserializeUser(function(id, done) {
    User.findById(id)
        .then(function(user) {
            done(null, user);
        })
        .catch(function(err) {
            done(err, null);
        });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3002/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope:  ['https://www.googleapis.com/auth/plus.login',
  'https://www.googleapis.com/auth/userinfo.email'] }
));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets
    res.redirect('/secrets');
  }
);

// Error handling middleware
app.use(function(err, req, res, next) {
  if (err instanceof InternalOAuthError) {
    console.error("OAuth error:", err.message);
    // Handle the OAuth error gracefully (e.g., redirect to a login page with an error message)
    res.redirect('/login?error=oauth');
  } else {
    next(err);
  }
});


app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret":{$ne:null}})
    .then((foundUsers)=>{
        if(foundUsers){
            res.render("secrets",{usersWithSecrets: foundUsers})
        }
    })
    .catch((err)=>{
        console.log(err);
    })

});

app.get("/submit",function(req,res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})



app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
        }
        // Redirect after logout
        res.redirect("/");
    });
});

app.post("/register", (req, res) => {
    User.register(new User({ username: req.body.username }), req.body.password, (err, user) => {
        if (err) {
            console.error(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.logIn(user, (err) => {
        if (err) {
            console.error(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});


app.post("/submit" ,function(req,res){
    const submittedSecret= req.body.secret;
    User.findById(req.user.id)
    .then(function(foundUser){
        if (foundUser)
        {
            foundUser.secret= submittedSecret;
            foundUser.save()
            .then(()=>{
                res.redirect("/secrets");
            })
        }
    })
    .catch((err)=>{
        console.log(err);
    })
});



app.listen(3002, () => {
    console.log("Server is listening on port 3002");
});


