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

test('authgw configuration', t => {
  t.plan(3);

  let opts = {tokenHeader: 'some-header'};
  let authgw = new AuthGW(['admin'], 'myapp', [], opts);

  t.equal(authgw.opts.tokenHeader, 'some-header', 'should allow overrides');
  t.equal(authgw.opts.tokenExpiredCode, 419, 'should retain defaults');

  t.doesNotThrow(
    () => new AuthGW(null, 'myapp', [], opts), null,
    'should allow roles to be empty'
  );
});
