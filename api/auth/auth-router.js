const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model');
const bcrypt = require("bcryptjs/dist/bcrypt");

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: '1d',
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password, role_name } = req.body;
  Users.add({ username, password, role_name })
  .then(newUser => {
    res.status(201).json(newUser)
  })
  .catch(err => {
    next(err)
  })
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { user_id, password } = req.body;
  Users.findById({ user_id })
  .then(user => {
    if(user && bcrypt.compareSync(password, user.password)) {
      const token = generateToken(user);
      next({
        status: 200,
        message: `${user.username} is back!`,
        token,
      });
    } else {
      res.status(401).json({ message: 'Invalid Credentials'})
    }
  })
});

module.exports = router;
