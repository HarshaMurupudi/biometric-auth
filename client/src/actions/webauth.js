import axios from 'axios';
import base64url from 'base64url';

import {
  preformatMakeCredReq,
  publicKeyCredentialToJSON,
  preformatGetAssertReq
} from '../utils/webauth';

import {
  USER_LOADED,
  USER_LOADING,
  LOGIN_SUCCESS,
  AUTH_ERROR
} from './types';

import { loadUser } from './auth';
import { setAlert } from './alert'

// another function to go from string to ByteArray, but we first encode the
// string as base64 - note the use of the atob() function
function strToBin(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// function to encode raw binary to string, which is subsequently
// encoded to base64 - note the use of the btoa() function
function binToStr(bin) {
  return btoa(new Uint8Array(bin).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  ));
};

let getMakeCredentialsChallenge = async () => {
  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
    // credentials: 'include',
  }
  const body = JSON.stringify()

  try {
    const response = await axios.post('api/webauth/register', body, config)
    return response.data;

  } catch (error) {
    alert(error)
    throw Error("Server error")
  }
}

let sendWebAuthnResponse = async (payload, type) => {
  const api = type === 'register' ? 'api/webauth/register/response' : 'api/webauth/login/response'

  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
    // credentials: 'include',
  }
  const body = JSON.stringify(payload);
  try {
    const response = await axios.post(api, body, config);

    return response;
  } catch (error) {
    alert(error)
    throw Error("Server error")
  }
}

let getGetAssertionChallenge = async (id) => {
  const config = {
    headers: {
      'Content-Type': 'application/json'
    },
  }
  const body = JSON.stringify({ id });

  const response = await axios.post('api/webauth/login', body, config)

  console.log(response)
  const { data } = response;

  if (data.status !== 'ok') {
    throw new Error(`Server responed with error. The message is: ${response.message}`);
  }
  else {
    return data;
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
      payload: res.data
    });
    dispatch(loadUser())
  } catch (error) {
    dispatch(setAlert("Biometric authentication failed", 'danger'))
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
      challenge: Buffer.from(base64url.decode(response.challenge), 'base64'),
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
    // alert(cred)
    let getAssertionResponse = publicKeyCredentialToJSON(cred);
    getAssertionResponse.userId = userId;
    const loginRes = await sendWebAuthnResponse(getAssertionResponse, 'login');
    dispatch({
      type: LOGIN_SUCCESS,
      payload: loginRes.data
    });

    dispatch(loadUser())

  } catch (error) {
    // alert(error)
    dispatch({
      type: AUTH_ERROR
    });
  }
}