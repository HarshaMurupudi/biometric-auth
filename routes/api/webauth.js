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

  response.json(challengeMakeCred)
})

router.post('/register/response', auth, async (request, response) => {
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

    let result;
    if (webauthnResp.response.attestationObject !== undefined) {
      result = verifyAuthenticatorAttestationResponse(webauthnResp);

      if (result.verified) {
        const userFields = {
          authenticators: []
        };
        userFields.authenticators.push(result.authrInfo);
        userFields.bioauth = true;

        console.log(request.user.id)

        const user = await User.findOneAndUpdate(
          { _id: request.user.id },
          { $set: userFields },
          { new: true },
        );
        console.log(user)
        response.json(user)

      } else {
        response
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }
    } else {
      response.json({
        'status': 'failed',
        'message': 'Can not determine type of response!'
      })
    }
  } catch (error) {
    console.log(err)
    response.status(500).send('Server error');
  }
});

router.post('/login', async (request, response) => {
  const user = await User.findById(request.body.id)
  let getAssertion = generateServerGetAssertion(user.authenticators)
  getAssertion.status = 'ok'
  // request.session.challenge = getAssertion.challenge;
  // request.session.username = username;

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
    console.log(webauthnResp.userId, "fetching response")

    /* Check challenge... */
    // if (clientData.challenge !== request.session.challenge) {
    //   response.json({
    //     'status': 'failed',
    //     'message': 'Challenges don\'t match!'
    //   })
    // }

    /* ...and origin */
    // if (clientData.origin !== config.origin) {
    //   response.json({
    //     'status': 'failed',
    //     'message': 'Origins don\'t match!'
    //   })
    // }

    // const user = await User.findById(req.user.id)

    let result;
    if (webauthnResp.response.authenticatorData !== undefined) {
      const { userId } = webauthnResp;
      const user = await User.findById(userId)
      /* This is get assertion */
      result = verifyAuthenticatorAssertionResponse(webauthnResp, user.authenticators);

      if (result.verified) {
        console.log("login verfied")
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
      response.json({
        'status': 'failed',
        'message': 'Can not determine type of response!'
      })
    }

    if (result.verified) {
      // request.session.loggedIn = true;
      response.json({ 'status': 'ok' })
    } else {
      response
        .status(400)
        .json({ errors: [{ msg: 'Invalid Credentials' }] });
    }
  } catch (err) {
    console.log(err)
    response.status(500).send('Server error');
  }
});

module.exports = router;
