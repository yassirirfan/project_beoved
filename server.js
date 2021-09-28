require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const passport = require('passport'), LocalStrategy = require('passport-local').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const session = require("express-session");
const { access } = require('fs');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const { Db } = require('mongoose/node_modules/mongodb');
const flash = require('connect-flash');



const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret:"We love you more",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());



mongoose.connect(process.env.MONGO_URL,{useNewUrlParser:true});

//mongoose.set("useCreateIndex", true);

//Schemas

const userSchema = new mongoose.Schema({
    name:String,
    googleId:String,
    email:String,
    password:String
})
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
userSchema.methods.validPassword = function( pwd ) {
    return ( this.password === pwd );
};

const User = new mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
    name:String,
    title:String,
    content:String,
    time:String
})
const Post = new mongoose.model("Post", postSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/profile"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({user:profile.displayName,googleId: profile.id}, function (err, user) {
        return done(err, user) 
    });

  }
));

passport.use(new LocalStrategy({
    usernameField: 'loginUsername',
    passwordField: 'loginPassword'
    },
    function(username, password, done) {
      User.findOne({email: username }, function(err, user) {
        if (err) { return done(err); }
        if (!user) {
          return done(null, false, { message: 'Incorrect username.' });
        }
        if (!user.validPassword(password)) {
          return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
      });
    }
));

//Routes
app.get("/" , (req,res) => {
    res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/profile', 
  passport.authenticate('google', { failureRedirect: '/register' }),
  function(req, res) {
    res.redirect('/profile');
});

app.get("/register" , (req,res) => {
    res.render("register")
})

app.get("/profile", (req,res)=> {
    
    if(req.isAuthenticated()) {
        let name;
        if(req.user.name == undefined) name = req.user.googleId;
        else name = req.user.name;

        Post.find({"name":name} , (err,foundPosts) => {
            if(!err) res.render("profile", {userPosts: foundPosts, userName:name});
        }) 

    }
    else res.redirect("/register");
})

app.get("/success",(req,res) => {
    res.render("success")
})
app.get("/servErr",(req,res) => {
    res.render("servErr")
})
app.get("/error",(req,res) => {
    res.render("error")
})
app.get("/contact",(req,res) => {
    res.render("contact")
})
app.get("/feed", (req,res)=> {
    if(req.isAuthenticated()){
        Post.find((err,allPosts) => {
            if(!err) res.render("feed", {Posts : allPosts})
        })
    } 
    else res.redirect("/register")
})

app.post("/register",(req,res) => {
    const newEmail = req.body.usrEmail;
    const newPassword1 = req.body.usrPassword;
    const newPassword2 = req.body.usrConfirmPassword;

    //User Register Authentication Process
    User.findOne({email:newEmail}, (err,data) => {
        if(data) res.send("Email Already Registered");
        else{
            if(newPassword1 === newPassword2){
                const user = new User({
                    name:Date.now() + Math.floor(Math.random()*10),
                    email:newEmail,
                    password:newPassword1
                })
                user.save((err) => {
                    if(!err) res.redirect("/success");
                    else {
                        res.redirect("/servErr")
                        console.log(err)
                    } 
                })
            }
            else res.send("Password donot match"); 
        }
    })
})

app.post('/login',
  passport.authenticate('local', { successRedirect: '/profile',
                                   failureRedirect: '/register',
                                   failureFlash: true })
);



app.post("/submit-post" , (req,res) => {

        if(req.isAuthenticated()){
            
            let name;
            if(req.user.name == undefined) name = req.user.googleId;
            else name = req.user.name;

            const post = new Post ({
                name:name,
                title:req.body.postTitle,
                content:req.body.postContent,
                time:new Date().getDate()
            })
    
            if(post.title.length  > 5 && post.content.length > 25){
                post.save((err) => {
                    if(!err) res.redirect("/success");
                    else {
                        res.redirect("/servErr")
                        console.log(err)
                    } 
                })
            }
    
            else {
                res.send("Empty post")
            }
        }
        else res.redirect("/register")


})
app.get("/delete-post", (req,res) => {
    console.log(req.body.postID)
})


//Hosting
app.listen(3000, () => {
    console.log("Server Ready")
})