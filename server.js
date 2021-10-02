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
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.set('view engine', 'ejs');
app.use(express.static("public"));


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
    name: String,
    email:String,
    password: String,
    googleId: String
})
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

userSchema.methods.validPassword = function( pwd ) {
    return bcrypt.compareSync(pwd,this.password);
};
 
const User = new mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
    name:String,
    title:String,
    content:String,
    commentsArray:[],
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
    function(username,password, done) {
      
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
                bcrypt.hash(newPassword1,saltRounds,(err,hash) => {
                    if(!err){
                        const user = new User({
                            name:  Date.now() + Math.floor(Math.random()*10),
                            email:newEmail,
                            password:hash
                        })
                        user.save((err) => {
                            if(!err) res.redirect("/success");
                            else {
                                res.redirect("/servErr")
                                console.log(err)
                            } 
                        })
                    }
                    else console.log(err)
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

            const monthNames = ["January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"];
            const dateObj = new Date();
            const month = monthNames[dateObj.getMonth()];
            const day = String(dateObj.getDate()).padStart(2, '0');
            const year = dateObj.getFullYear();
            const output = month  + '\n'+ day  + ', ' + year;

            const post = new Post ({
                name:name,
                title:req.body.postTitle,
                content:req.body.postContent,
                time:output
            })
    
            if(post.title.length  > 5 && post.content.length > 25){
                post.save((err) => {
                    if(!err) res.redirect("/profile");
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
app.get("/delete/:id", (req,res) => {
    Post.findOneAndDelete({_id:req.params.id}, (err,data) => {
        if(!err) res.redirect("/profile");
        else console.log(err)
    })
})
app.get("/changePassword/:id", (req,res) => {
    User.findOne({_id:req.params.id},(err,data) => {
        if(!err){
            res.render("changePassword")
        }
    })
})

app.post("/changePassword/:id", (req,res) => {
    User.findOne({_id:req.params.id},(err,data) => {
        if(!err){
            res.render("changePassword")
        }
    })
})

app.get("/read/:id",(req,res) => {
    Post.findOne({_id:req.params.id} ,(err, data) => {
        if(!err) res.render("read",{postsData:data,comments:data.commentsArray})
        else console.log(err)
    })
})

app.post("/comment/:id", (req,res) => {
    if(req.isAuthenticated()){
        const newComment = req.body.comment;
        let name;
        if(req.user.name == undefined) name = req.user.googleId;
        else name = req.user.name;
        const id = req.params.id;

        const monthNames = ["January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"];
        const dateObj = new Date();
        const month = monthNames[dateObj.getMonth()];
        const day = String(dateObj.getDate()).padStart(2, '0');
        const year = dateObj.getFullYear();
        const output = month  + '\n'+ day  + ', ' + year;

        const newCommentObj = {
            user:name,
            comment:newComment,
            time:output
        }

        Post.findOneAndUpdate(
            { _id: req.params.id }, 
            { $push: { commentsArray: newCommentObj  } },
           function (error, success) {
                if (error) console.log(error);
                else res.redirect("/read/" + id);
        });
    }
    else res.redirect("/register")
})

//Hosting
app.listen(3000, () => {
    console.log("Server Ready")
})