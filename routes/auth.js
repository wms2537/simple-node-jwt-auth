const path = require('path');

const express = require('express');
const {
  body
} = require('express-validator');

const User = require('../models/user');
const authController = require('../controllers/auth');
const { isAuth } = require('../middlewares/is-auth');

const router = express.Router();

router.post(
  '/signup', [
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email.')
    .custom((value, {
      req
    }) => {
      return User.findOne({
        email: value
      }).then(userDoc => {
        if (userDoc) {
          return Promise.reject('E-Mail address already registered!');
        }
      });
    })
    .normalizeEmail(),
  body('password')
    .trim()
    .isLength({
      min: 5
    }),
],
  authController.signup
);

router.post('/sign_in_with_email_password', [
  body('email')
    .notEmpty()
    .trim(),
  body('password')
    .trim()
    .isLength({
      min: 5
    })
], authController.signInWithEmailPassword, authController.handleSignIn);

router.get('/sendVerificationEmail', isAuth, authController.sendVerificationEmail);

router.get('/verifyEmail/:token', authController.verifyEmail);

router.post('/sendPasswordResetEmail/:email', [body('token')
  .trim()
  .notEmpty()
], authController.sendPasswordResetEmail);

router.get('/resetPassword/:token', authController.resetPassword);

router.get('/resetPassword', (req, res, next) => res.sendFile(path.join(__dirname, '..', 'templates', 'reset_password.html')));

router.get('/emailAvailability/:email', authController.getEmailAvailability);

router.get('/publicKey', authController.getPublicKey);

router.post('/refreshToken', [
  body('accessToken')
    .notEmpty()
    .trim(),
  body('refreshToken')
    .notEmpty()
    .trim()
], authController.refreshToken);


module.exports = router;