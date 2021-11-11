import React, { Fragment, useState } from 'react'
import { Link, Redirect } from 'react-router-dom';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { login } from '../../actions/auth';
import { webauthLogin } from '../../actions/webauth';

const Login = ({ login, webauthLogin, isAuthenticated }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const { email, password } = formData;
  const onChange = e => setFormData({ ...formData, [e.target.name]: e.target.value })
  const onSubmit = async e => {
    e.preventDefault();
    login(email, password);
  }
  const onBiometricLoginClick = e => {
    const { userId } = JSON.parse(localStorage.getItem('bioauthConfig'));

    webauthLogin({ userId })
  }

  if (isAuthenticated) {
    return <Redirect to="/profile" />;
  }

  const isBioauthEnabled = () => {
    const bioauthConfig = JSON.parse(localStorage.getItem('bioauthConfig'));

    if (bioauthConfig) {
      return true;
    } else {
      return false;
    }
  }

  return (
    <Fragment>
      <h1 className="large text-primary">Sign In</h1>
      <p className="lead"><i className="fas fa-user"></i> Sign Into Your Account</p>
      <form className="form" onSubmit={e => onSubmit(e)}>
        <div className="form-group">
          <input
            type="email"
            placeholder="Email 
            Address" name="email"
            required
            value={email}
            onChange={e => onChange(e)}
          />
        </div>
        <div className="form-group">
          <input
            type="password"
            placeholder="Password"
            name="password"
            minLength="6"
            required
            value={password}
            onChange={e => onChange(e)}
          />
        </div>
        <input type="submit" className="btn btn-primary" value="Login" />
      </form>

      {isBioauthEnabled() && <div>
        <h4>or</h4>
        <input type="submit" className="btn btn-primary" value="Biometric Login" onClick={e => onBiometricLoginClick(e)} />
      </div>
      }

      <p className="my-1">
        Don't have an account? <Link to="/register">Register</Link>
      </p>
    </Fragment>
  )
}

Login.propTypes = {
  login: PropTypes.func.isRequired,
  webauthLogin: PropTypes.func.isRequired,
  isAuthenticated: PropTypes.bool,
}

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated
});

export default connect(mapStateToProps, { login, webauthLogin })(Login);
