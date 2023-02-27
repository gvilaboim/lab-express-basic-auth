const router = require("express").Router();
const User = require('../models/User.model')
const mongoose = require("mongoose");

const bcryptjs = require('bcryptjs')
const saltRounds = 10
const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard");

/* GET home page */
router.get("/", (req, res, next) => {
    res.redirect("/login");
});

router.get('/signup', isLoggedOut,(req, res) => res.render('auth/signup' , {layout: 'login-layout.hbs'}))
router.get('/userProfile', isLoggedIn, (req, res) => {
    res.render('auth/user-profile', { userInSession: req.session.currentUser ,    layout: 'loggedin-layout.hbs'});
  });


router.post("/signup", isLoggedOut, (req, res, next) => {
    // console.log("The form data: ", req.body);
  
    const { username, password } = req.body;
  
    // make sure users fill all mandatory fields:
    if (!username || !password) {
      res.render("auth/signup", {
        errorMessage: "All fields are mandatory. Please provide your username, email and password.",
        layout: '/login-layout.hbs'

      });
      return;
    }
  
    // make sure passwords are strong:
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
      res.status(500).render("auth/signup", {
        errorMessage:
          "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
          layout: '/login-layout.hbs'

      });
      return;
    }
  
    bcryptjs
      .genSalt(saltRounds)
      .then((salt) => bcryptjs.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({
          // username: username
          username,
          password: hashedPassword
        });
      })
      .then((userFromDB) => {
        // console.log("Newly created user is: ", userFromDB);
        res.redirect("/userProfile");
      })
      .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
          res.status(500).render("auth/signup", { errorMessage: error.message });
        } else if (error.code === 11000) {
          res.status(500).render("auth/signup", {
            errorMessage: "Username and email need to be unique. Either username or email is already used.",
            layout: '/login-layout.hbs'

          });
        } else {
          next(error);
        }
      }); // close .catch()
  });

router.get("/login", isLoggedOut, (req, res) => res.render("auth/login", {layout: 'login-layout.hbs' }));

// POST login route ==> to process form data
//                     .: ADDED :.

router.post("/login", isLoggedOut, async (req, res, next) => {
  console.log("SESSION =====> ", req.session);
  const { username, password } = req.body;

  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
      layout: '/login-layout.hbs'
    });
    return;
  }

  User.findOne({ username }) // <== check if there's user with the provided email
    .then((user) => {
      // <== "user" here is just a placeholder and represents the response from the DB
      console.log(user)
      if (!user) {
        // <== if there's no user with provided email, notify the user who is trying to login
        res.render("auth/login", {
          errorMessage: "Email is not registered. Try with other email.",
          layout: '/login-layout.hbs'
        });
        return;
      }
      // if there's a user, compare provided password
      // with the hashed password saved in the database
      else if (bcryptjs.compareSync(password, user.password)) {
    
        req.session.currentUser = user;
        res.redirect("/userProfile");
      } else {
        // if the two passwords DON'T match, render the login form again
        // and send the error message to the user
        res.render("auth/login", {
          errorMessage: "Incorrect password.",
          layout: '/login-layout.hbs'
        });
      }
    })
    .catch((error) => next(error));
});

router.post("/logout", isLoggedIn, (req, res) => {
    req.session.destroy();
    res.redirect("/login");
  });


  router.get('/main', isLoggedIn, (req, res) => {
    res.render('main', { userInSession: req.session.currentUser ,    layout: 'loggedin-layout.hbs'});
  });

  
  router.get('/private', isLoggedIn, (req, res) => {
    res.render('private', { userInSession: req.session.currentUser ,    layout: 'loggedin-layout.hbs'});
  });



module.exports = router;
