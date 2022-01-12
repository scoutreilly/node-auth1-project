// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express");
const router = express.Router();
const {
  restricted,
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists,
  checkPayload,
} = require("../auth/auth-middleware");
const userModel = require("../users/users-model");
const bcrypt = require("bcryptjs");
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
//check payload
router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  checkPayload,
  async (req, res) => {
    try {
      // the ten means 2 to the 10th power, hashing password that many times
      const hash = bcrypt.hashSync(req.body.password, 11);
      const newUser = await userModel.add({
        username: req.body.username,
        password: hash,
      });
      res.status(200).json(newUser);
    } catch (e) {
      res.status(422).json({ message: "Username taken" });
    }
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
//check payload
router.post("/login", checkUsernameExists, checkPayload, (req, res) => {
  try {
    const verified = bcrypt.compareSync(
      req.body.password,
      req.userData.password
    );
    if (verified) {
      //a session is a browser session, only on https, http is not session secure
      //sessions use cookies
      //create session
      req.session.user = req.userData;
      res.status(200).json({ message: `Welcome ${req.body.username}!` });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", restricted, (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        res.status(500).json({ message: "Could not logout" });
      } else {
        res.status(200).json({ message: "logged out!" });
      }
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
