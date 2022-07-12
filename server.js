const express = require('express');
var cookieSession = require('cookie-session');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const connectDB = require('./config/db');

const app = express();

connectDB();

// Middleware
app.use(express.json({ extended: false }));

/* ----- session ----- */
app.use(
  cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],

    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  })
);
app.use(cookieParser());

//  Routes
app.use('/api/user', require('./routes/api/user'));
app.use('/api/auth', require('./routes/api/auth'));
app.use('/api/webauth', require('./routes/api/webauth'));

// Server static assets in production
if (process.env.NODE_ENV === 'production') {
  // Set static folder
  app.use(express.static('client/build'));

  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
  });
}

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
