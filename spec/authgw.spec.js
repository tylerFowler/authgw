'use strict';

const test    = require('tape');
const express = require('express');
const AuthGW  = require('../lib/authgw');

const createAuthGWHarness = authgw => {
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
