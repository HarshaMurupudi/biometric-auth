const express = require('express');

const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  check,
  validationResult
} = require('express-validator/check');

const config = require('config');
const auth = require('../../middleware/auth');
const User = require('../../models/User');

const router = express.Router();

router.post(
  '/register',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more charaters').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email });

      if (user) {
        return res.status(400).json({ errors: [{ msg: "User already exists" }] });
      }

      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });
      const salt = await bcrypt.genSalt(10);

      user = new User({
        name,
        email,
        avatar,
        password
      })

      user.password = await bcrypt.hash(password, salt);
      await user.save();

      const userDetailsJWT = {
        user: {
          id: user.id
        }
      }

      jwt.sign(
        userDetailsJWT,
        config.get('jwtSecret'),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );

    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server error');
    }
  });

router.post(
  '/update',
  auth,
  async (req, res) => {
    const { bioauth } = req.body;
    const userFields = {
      bioauth,
      authenticators: []
    }

    try {
      const user = await User.findOneAndUpdate(
        { _id: req.user.id },
        { $set: userFields },
        { new: true }
      );

      if (user) {
        return res.json(user);
      } else {
        throw Error('User not found')
      }

    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server Error')
    }
  }
)


module.exports = router;
