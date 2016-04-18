'use strict';

const test    = require('tape');
const express = require('express');
const AuthGW  = require('../lib/authgw');

const createApp = authgw => {
  let app = express();

  app.set('authgw', authgw);
  app.use(authgw.middleware());
  return app;
};

test('AuthGW configuration', t => {
  t.plan(3);

  let opts = { tokenHeader: 'some-header' };
  let authgw = new AuthGW(['admin'], 'myapp', [], opts);

  t.equal(authgw.opts.tokenHeader, 'some-header', 'should allow overrides');
  t.equal(authgw.opts.tokenExpiredCode, 419, 'should retain defaults');

  t.doesNotThrow(
    () => new AuthGW(null, 'myapp', [], opts), null,
    'should allow roles to be empty'
  );
});

test('AuthGW async token creation and validation', t => {
  const schema = [
    { name: 'userid', required: true },
    { name: 'username', required: false }
  ];

  let authgw = new AuthGW(['user', 'admin'], 'myapp', schema);

  authgw.createToken({userid: 1234, username: 'tyler'}, 'admin', 30)
  .then(token => {
    t.assert(token, 'Token should exist');

    return authgw.verifyToken(token);
  })
  .then(unwrapped => {
    t.equal(unwrapped.data.userid, 1234, 'Token userid should match');
    t.equal(unwrapped.data.username, 'tyler', 'Token username should match');
    t.equal(unwrapped.role, 'admin', 'Token role should match');
    t.end();
  })
  .catch(err => { t.error(err); t.end(); });
});

test('AuthGW sync token creation and validation', t => {
  const schema = [{ name: 'userid', required: true }];
  let authgw = new AuthGW(['user', 'admin'], 'myapp', schema);

  try {
    let token =
    authgw.createTokenSync({userid: 1234, username: 'tyler'}, 'admin', 30);

    t.assert(token, 'Token should exist');

    let unwrapped = authgw.verifyTokenSync(token);
    t.equal(unwrapped.data.userid, 1234, 'Token userid should match');
    t.equal(unwrapped.data.username, 'tyler', 'Token username should match');
    t.equal(unwrapped.role, 'admin', 'Token role should match');
    t.end();
  } catch (err) { t.error(err); t.end(); }
});

test('Verify token express middleware', t => {
  const schema = [
    { name: 'userid', required: true },
    { name: 'username', required: false }
  ];

  let authgw = new AuthGW(['user', 'admin'], 'myapp', schema);
  let verifyTokenFn = AuthGW.Middleware.verifyTokenExpress.call(authgw);

  let runTest = (token, cb) => {
    let req = {headers: { 'x-access-token': token }};
    let res = {
      statusCode: null, msg: null, sendHook: null,
      status: function status(s) { this.statusCode = s; return this; },
      sendStatus: function sendStatus(s) {
        this.statusCode = s;
        if (this.sendHook) this.sendHook(this);
        return this;
      },

      send: function send(msg) {
        this.msg = msg;
        if (this.sendHook) this.sendHook(this);
        return this;
      }
    };

    res.sendHook = response => cb(null, req, response);
    verifyTokenFn(req, res, nextErr => cb(nextErr, req, res));
  };

  t.plan(6);

  // Regular Successful Verification
  let userData = { userid: 1234, username: 'tyler' };
  let validToken = authgw.createTokenSync(userData, 'admin', 10);
  runTest(validToken, (err, req) => {
    t.comment('Valid Token Verification');
    if (err) { t.error(err); t.end(); }
    t.assert(req._tokenData, 'Data should have been injected into request');
    t.equal(req._tokenData.userid, userData.userid, 'Data should match the token');
    t.equal(req.userRole, 'admin', 'Should write the token role to req');
  });

  // Invalid/Malformed Token
  runTest('notatoken', (err, req, res) => {
    t.comment('Invalid/Malformed Token');
    if (err) { t.error(err); return t.end(); }

    t.equal(res.statusCode, 401, 'Error for malformed token should be 401');
  });

  // Empty Token Data
  runTest(null, (err, req) => {
    t.comment('Empty Token');
    if (err) { t.error(err); return t.end(); }

    t.notok(req._tokenData, 'Token data should not be written');
    t.notok(req.userRole, 'Token role should not be written');
  });
});
