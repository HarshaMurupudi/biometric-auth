import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types'
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import Switch from "react-switch";

import { webauthRegister } from '../../actions/webauth';
import { updateUser } from '../../actions/user';
import { isWebauthnAvailable } from '../../utils/webauth';
// import {
//   binToStr
// } from '../utils/webauth';

const Profile = ({ webauthRegister, updateUser, auth, profile, history }) => {
  useEffect(() => {
    const bioauthConfig = localStorage.getItem('bioauthConfig');

    if (auth.user) {
      if (!bioauthConfig && auth.user.bioauth) {
        const bioauthConfig = {
          // rawId: base64url.decode(auth.user.authenticators[0].credId),
          rawId: auth.user.authenticators[0].credId,
          userId: auth.user._id
        }

        localStorage.setItem('bioauthConfig', JSON.stringify(bioauthConfig))
      }
    }
  }, [auth.user]);
  const [data, updateData] = useState({});

  useEffect(() => {
    const getData = async () => {
      const resp = await isWebauthnAvailable();
      // const json = await resp.json()
      updateData(resp);
    }
    getData();
  }, []);

  const onChange = async e => {
    if (auth.user.bioauth) {
      await updateUser({ bioauth: !auth.user.bioauth }, history);
      localStorage.removeItem("bioauthConfig");
    } else {
      await webauthRegister(auth.user._id);
    }
  }

  const renderWebAuthnToogle = () => {
    const { status, message } = data;

    if (status) {
      return <Switch onChange={onChange} checked={auth.user ? auth.user.bioauth : false} />
    }
    else {
      return <p>Sorry, {`${message}`}</p>
    }
  }

  return (
    <div className="profile">
      <h1>
        Profile
      </h1>
      {
        auth.loading ? <div>Loading...</div> : (
          <div className="my-3">
            <h2>Welcome <i>{auth.user.name}</i></h2>
            <label>
              <h6>Biometric Authentication</h6>
              {renderWebAuthnToogle()}
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
