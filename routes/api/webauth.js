const express = require('express');

const base64url = require('base64url');
const jwt = require('jsonwebtoken');
const config = require('config');

const User = require('../../models/User');

const auth = require('../../middleware/auth');
const {
  generateServerMakeCredRequest,
  verifyAuthenticatorAttestationResponse
} = require('../../utils/webauth/registration')
const {
  generateServerGetAssertion,
  verifyAuthenticatorAssertionResponse
} = require('../../utils/webauth/authentication')

const router = express.Router();

router.post('/register', auth, async (request, response) => {
  const user = await User.findById(request.user.id).select('-password');
  let challengeMakeCred = generateServerMakeCredRequest(user.email, user.name, user.id)
  challengeMakeCred.status = 'ok'

  request.session.challenge = challengeMakeCred.challenge;
  request.session.username = user.email;

  response.json(challengeMakeCred)
})

router.post('/register/response', auth, async (request, response) => {
  try {
    if (!request.body || !request.body.id
      || !request.body.rawId || !request.body.response
      || !request.body.type || request.body.type !== 'public-key') {
      response
        .json({
          'status': 'failed',
          'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })

      return
    }

    let webauthnResp = request.body;
    let clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if (clientData.challenge !== request.session.challenge) {
      return response
        .status(400)
        .json({
          errors: [{ msg: 'Challenges don\'t match!' }]
        })
    }

    let result;
    if (webauthnResp.response.attestationObject !== undefined) {
      result = verifyAuthenticatorAttestationResponse(webauthnResp);

      if (result.verified) {
        const userFields = {
          authenticators: []
        };
        userFields.authenticators.push(result.authrInfo);
        userFields.bioauth = true;

        const user = await User.findOneAndUpdate(
          { _id: request.user.id },
          { $set: userFields },
          { new: true },
        );
        response.json(user)

      } else {
        return response
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }
    } else {
      return response.json({
        'status': 'failed',
        'message': 'Can not determine type of response!'
      })
    }
  } catch (error) {
    console.log(error)
    response.status(500).send('Server error');
  }
});

router.post('/login', async (request, response) => {
  const user = await User.findById(request.body.id)
  let getAssertion = generateServerGetAssertion(user.authenticators)
  getAssertion.status = 'ok'
  request.session.challenge = getAssertion.challenge;
  request.session.username = user.email;

  response.json(getAssertion)
});

router.post('/login/response', async (request, response) => {

  try {
    if (!request.body || !request.body.id
      || !request.body.rawId || !request.body.response
      || !request.body.type || request.body.type !== 'public-key') {
      response.json({
        'status': 'failed',
        'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
      })

      return
    }

    let webauthnResp = request.body
    let clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if (clientData.challenge !== request.session.challenge) {
      return response
        .status(400)
        .json({
          errors: [{ msg: 'Challenges don\'t match!' }]
        })
    }

    /* ...and origin */
    // if (clientData.origin !== config.origin) {
    //   response.json({
    //     'status': 'failed',
    //     'message': 'Origins don\'t match!'
    //   })
    // }

    let result;
    if (webauthnResp.response.authenticatorData !== undefined) {
      const { userId } = webauthnResp;
      const user = await User.findById(userId)
      /* This is get assertion */
      result = verifyAuthenticatorAssertionResponse(webauthnResp, user.authenticators);

      if (result.verified) {
        const payload = {
          user: {
            id: userId
          }
        }

        return jwt.sign(
          payload,
          config.get('jwtSecret'),
          { expiresIn: 360000 },
          (err, token) => {
            if (err) throw err;
            return response.json({ token });
          }
        );
      }
      else {
        console.log("error verifcation")
        return response
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }
    } else {
      return response
        .status(400)
        .json({
          errors: [{ msg: 'Can not determine type of response!' }]
        })
    }
  } catch (err) {
    console.log(err)
    response.status(500).send('Server error');
  }
});

module.exports = router;
