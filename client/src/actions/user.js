import axios from 'axios';
import { setAlert } from './alert';
import {
  USER_LOADED,
  USER_UPDATE_ERROR
} from './types';
import { loadUser } from './auth';

export const updateUser = (formData, history) => async dispatch => {
  try {
    const config = {
      headers: {
        'Content-Type': 'application/json'
      }
    }
    const res = await axios.post('/api/user/update', formData, config);

    dispatch({
      type: USER_LOADED,
      payload: res.data
    });

    dispatch(loadUser())
  } catch (err) {
    const errors = err.response.data.errors;

    if (errors) {
      errors.forEach(error => dispatch(setAlert(error.msg, 'danger')));
    }
  }
}