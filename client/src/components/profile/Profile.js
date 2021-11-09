import React from 'react';
import PropTypes from 'prop-types'
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import Switch from "react-switch";

import { webauthRegister } from '../../actions/webauth';
import { updateUser } from '../../actions/user';

const Profile = ({ webauthRegister, updateUser, auth, profile, history }) => {
  const onChange = async e => {
    console.log("hit on change");

    if (auth.user.bioauth) {
      await updateUser({ bioauth: !auth.user.bioauth }, history);
      localStorage.removeItem("bioauthConfig");
    } else {
      await webauthRegister(auth.user._id);
    }
  }


  return (
    <div>
      <h1>
        Profile
      </h1>
      {
        auth.loading ? <div>Loading...</div> : (
          <div className="my-3">
            <h2>Welcome <i>{auth.user.name}</i></h2>
            <label>
              <h6>Biometric Authentication</h6>
              <Switch onChange={onChange} checked={auth.user ? auth.user.bioauth : false} />
            </label>
          </div>
        )
      }
    </div>
  )
}

Profile.propTypes = {
  auth: PropTypes.object.isRequired,
};

const mapStateToProps = state => ({
  auth: state.auth,
})

export default connect(mapStateToProps, { webauthRegister, updateUser })(withRouter(Profile));
