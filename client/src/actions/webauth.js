import axios from 'axios';
import base64url from 'base64url';

import {
  preformatMakeCredReq,
  publicKeyCredentialToJSON,
  preformatGetAssertReq,
  strToBin,
  binToStr
} from '../utils/webauth';

import {
  USER_LOADED,
  USER_LOADING,
  LOGIN_SUCCESS,
  AUTH_ERROR
} from './types';

import { loadUser } from './auth';
import { setAlert } from './alert'

let getMakeCredentialsChallenge = async () => {
  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
  }
  const body = JSON.stringify()

  try {
    const response = await axios.post('api/webauth/register', body, config)
    return response.data;
  } catch (error) {
    throw error;
  }
}

let sendWebAuthnResponse = async (payload, type) => {
  const api = type === 'register' ? 'api/webauth/register/response' : 'api/webauth/login/response'

  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
  }
  const body = JSON.stringify(payload);
  try {
    const response = await axios.post(api, body, config);
    return response.data;
  } catch (error) {
    throw error;
  }
}

let getGetAssertionChallenge = async (id) => {
  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
  }
  const body = JSON.stringify({ id });

  try {
    const response = await axios.post('api/webauth/login', body, config)
    return response.data;
  } catch (error) {
    return error;
  }
}

export const webauthRegister = (userId) => async dispatch => {
  try {
    // Obtain the challenge and other options from server endpoint
    const credChallengeRes = await getMakeCredentialsChallenge();
    // Create a credential
    let publicKey = preformatMakeCredReq(credChallengeRes);
    const cred = await navigator.credentials.create({ publicKey });

    const locallyStoredBioauthConfig = {
      rawId: binToStr(cred.rawId),
      userId
    }
    localStorage.setItem('bioauthConfig', JSON.stringify(locallyStoredBioauthConfig));

    dispatch({
      type: USER_LOADING,
      payload: { loading: true }
    });
    // Register the credential to the server endpoint
    let makeCredResponse = publicKeyCredentialToJSON(cred);
    const res = await sendWebAuthnResponse(makeCredResponse, 'register');

    dispatch({
      type: USER_LOADED,
      payload: res
    });
    dispatch(loadUser())
  } catch (error) {
    const errors = error.response.data.errors;
    if (errors) {
      errors.forEach(error => dispatch(setAlert(error.msg, 'danger')));
    }
    dispatch({
      type: USER_LOADING,
      payload: { loading: false }
    });
  }
}

export const webauthLogin = ({ userId }) => async dispatch => {
  try {
    const response = await getGetAssertionChallenge(userId);
    // let publicKey = preformatGetAssertReq(response);
    const { rawId } = JSON.parse(localStorage.getItem('bioauthConfig'));
    const testPubKey = {
      challenge: base64url.toBuffer(response.challenge),
      allowCredentials: [{
        id: strToBin(rawId),
        type: 'public-key',
        // transports: ["internal"]
      }],
      authenticatorSelection: {
        userVerification: "platform"
      },
    }
    const cred = await navigator.credentials.get({ publicKey: testPubKey });
    // const cred = await navigator.credentials.get({ publicKey });
    let getAssertionResponse = publicKeyCredentialToJSON(cred);
    getAssertionResponse.userId = userId;
    const loginRes = await sendWebAuthnResponse(getAssertionResponse, 'login');
    dispatch({
      type: LOGIN_SUCCESS,
      payload: loginRes
    });

    dispatch(loadUser())
  } catch (error) {
    const errors = error.response.data.errors;
    if (errors) {
      errors.forEach(error => dispatch(setAlert(error.msg, 'danger')));
    }
    dispatch({
      type: AUTH_ERROR
    });
  }
}