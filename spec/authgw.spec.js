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

test.only('Data Injection Middleware', t => {
  let runWith = (schema, data, cb) => {
    const authgw = new AuthGW(['admin'], 'myapp', schema);
    let injectDataFn = AuthGW.Middleware.injectTokenDataExpress.call(authgw);
    let req = { userRole: 'admin', _tokenData: data };

    injectDataFn(req, {}, err => cb(err, req));
  };

  t.plan(10);

  // Standard Request w/ No Missing Data
  runWith([{name: 'userid', required: true}], {userid: 'tyler'}, (err, req) => {
    t.comment('Valid Request - Required Only');
    if (err) { t.error(err); return t.end(); }

    t.equals(req.userid, 'tyler', 'UserID should be injected into request');
  });

  // Standard Request w/ No Missing Data & Optional Value
  runWith(
    [{ name: 'userid', required: true }, { name: 'username', required: false }],
    { userid: 1234, username: 'tyler' },
    (err, req) => {
      t.comment('Valid Request w/ Optional Val');
      if (err) { t.error(err); return t.end(); }

      t.equals(req.userid, 1234, 'UserID should be injected into request');
      t.equals(req.username, 'tyler', 'Optional key should be injected');
    }
  );

  // Missing Required
  runWith(
    [{name: 'reqOne', required: true}, {name: 'reqTwo', required: true}],
    { reqOne: true },
    (err, req) => {
      t.comment('Missing Required');
      t.assert(err, 'Should give an error');
      t.notok(req.reqOne, 'Should not write data that *was* given');
    }
  );

  // No Data
  runWith([{name: 'userid', required: true}], null, err => {
    t.comment('No Data Passed');
    t.notok(err, 'Should not give an error');
  });

  // Extra Data
  runWith(
    [{name: 'userid', required: true}], {userid: 'tyler', extra: true},
    (err, req) => {
      t.comment('Extra Data');
      if (err) { t.error(err); return t.end(); }

      t.ok(req.userid, 'Required key should be injected');
      t.notok(req.extra, 'Extra key should not be injected');
    }
  );

  // Missing Optional
  let optionalSchema = [
    {name: 'userid', required: true}, {name: 'opt', required: false}
  ];

  runWith(optionalSchema, {userid: 'tyler'}, err => {
    t.comment('Missing Optional');
    if (err) { t.error(err); return t.end(); }
    t.assert(!err, 'Should not give error');
  });

  // Implicit Optional
  let implicitOptSchema = [{name: 'userid', required: true}, {name: 'opt'}];

  runWith(implicitOptSchema, {userid: 'tyler'}, err => {
    t.comment('Implicit Optional');
    if (err) { t.error(err); return t.end(); }
    t.assert(!err, 'Should not give error');
  });
});
