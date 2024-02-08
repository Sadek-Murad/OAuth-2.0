const express = require('express');
const sqlite3 = require('sqlite3').verbose(); 
const db = new sqlite3.Database('./database.db');
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

const cors = require('cors');
const corsOptions = {
  origin: 'http://localhost:3000',
  methods: 'GET,POST,PUT,DELETE',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, googleId TEXT, secret TEXT)");
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SCRET,
    callbackURL: "http://localhost:4000/auth/google/callback",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    db.get("SELECT * FROM users WHERE googleId = ?", [profile.id], (err, row) => {
      if (!row) {
        db.run("INSERT INTO users (username, name, googleId) VALUES (?, ?, ?)", [profile.displayName, profile.displayName, profile.id], (err) => {
          db.get("SELECT * FROM users WHERE googleId = ?", [profile.id], (err, newRow) => {
            return cb(err, newRow);
          });
        });
      } else {
        return cb(null, row);
      }
    });
  }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

passport.deserializeUser(function(id, done) {
    db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
      done(err, row);
    });
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  res.redirect('/');
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get("/", (req, res) => {
    res.send("Welcome to the homepage!");
});

db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error("Fehler beim Abrufen der Daten:", err);
    } else {
      console.log("Daten aus der Tabelle 'users':", rows);
    }
  });



const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
