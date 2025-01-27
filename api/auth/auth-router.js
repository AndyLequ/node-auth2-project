const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
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
  try {
    const { username, password, role_name = 'default_role'} = req.body
    const hash = bcrypt.hashSync(password, 8) // hash the password with a salt round of 8
    
    const user = await Users.add({ username, password: hash, role_name })
    
    
    res.status(201).json(user)
  } catch (err) {
    next(err)
  }
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
  try {
    const { username, password } = req.body
    if (bcrypt.compareSync(password, req.user.password)) {
      const token = jwt.sign({
        subject: req.user.user_id,
        username: req.user.username,
        role_name: req.user.role_name
      }, JWT_SECRET, {
        expiresIn: '1d'
      })
      res.json({
        message: `${req.user.username} is back!`,
        token
      })
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err)
  }
});

module.exports = router;
