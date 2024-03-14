// ----- Level 3 Authentication Salt password and improved Encryption ------
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
//allow us to set up a new session to start saving user login sessions.
import session from "express-session";
//
import passport from "passport";
// local strategy
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
// --- Number of saltRounds
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  // key used to keep the session secret
  secret: "TOPSECRETWORD",
  // wether we want to save the session in datastore (database)
  resave: false,
  // this will save the uninitialized session into server memory
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}))

// it's really important that your passport module goes after your session initialization
app.use(passport.initialize())
app.use(passport.session())


const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Authentication",
  password: "mpo58190",
  port: 5432,
});
db.connect();


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  // how do we known that our user is already logedin 
  // if we have an active session that save in a cookie then we straight away show them the secret page
  // isAuthenticated is comes from passport it allows us to check is the current user logged in in the current session authenticated already
  if (req.isAuthenticated) {
    res.render("secrets.ejs")
  } else {
    res.redirect("login")
  }
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      // Password Hashing
        bcrypt.hash(password, saltRounds, async (err, hash) =>{
            if (err) {
              console.log("Error hashing password", err)
            } else {
              const result = await db.query(
                "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
                [email, hash]
              );
              const user = result.rows[0];
              req.login(user, (err) => {
                console.log(err)
                res.redirect("/secrets")
              })
            }

          })
      }

     
      
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

//
passport.use(new Strategy(async function verify(username, password, cb) {
  console.log(username)
  console.log(password)

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      
      // order matters here (loginpassword, storedHashedpassword)
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err)
        } else {
          if (result) {
            return cb(null, user)
          } else {
            return cb(null, false)
          }
        } 
    });
  } else {
    return cb("User not found")
  }
  } catch (err) {
    return cb(err)

  }     
}));

passport.serializeUser((user, cb)=>{
  cb (null, user)
})

passport.deserializeUser((user, cb)=>{
  cb (null, user)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
