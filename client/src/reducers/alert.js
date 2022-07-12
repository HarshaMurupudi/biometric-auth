import { SET_ALERT, REMOVE_ALERT } from '../actions/types.js'

const initialState = [];

// eslint-disable-next-line import/no-anonymous-default-export
export default function (state = initialState, action) {
  const { type, payload } = action;

  console.log(type, payload);
  switch (type) {
    case SET_ALERT:
      return [...state, payload]
    case REMOVE_ALERT:
      return state.filter(alert => alert.id !== payload);
    default:
      return state;
  }
}