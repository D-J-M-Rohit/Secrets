//jshint esversion:6

import dotenv from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import PassportLocalMongoose from "passport-local-mongoose";
import findOrCreate from "mongoose-findorcreate";

const app = express();
dotenv.config();


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "iamrohit",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const mongo_url = process.env.MONGO_API_KEY;
mongoose.connect(mongo_url);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
});

userSchema.plugin(PassportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());

passport.deserializeUser(User.deserializeUser());

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } })
      .then(function (foundUsers) {
        if (foundUsers) {
          res.render("secrets", { usersWithSecrets: foundUsers });
        } else {
          // Handle case where no users with secrets were found
          res.render("submit");
        }
      })
      .catch(function (err) {
        console.log(err);
      });
  } else {
    res.render("login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  if (!req.isAuthenticated()) {
    // Handle the case where the user is not authenticated
    res.redirect("/login"); // or any other appropriate action
    return;
  }

  const submittedSecret = req.body.secret;

  User.findById(req.user.id)
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser
          .save()
          .then(() => {
            res.redirect("/secrets");
          })
          .catch((err) => {
            console.log(err);
          });
      }
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/logout", function (req, res) {
  req.logout((err) => {
    console.log(err);
  });
  res.redirect("/");
});

app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        // alert("A user with the given email is already registered!");
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", (req, res) => {
  if (req.body.username === "" || req.body.password === "") {
    res.redirect("/login");
  }
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, () => {
  console.log("Server is running");
});
