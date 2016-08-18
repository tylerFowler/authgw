const test    = require('tape');
const Promise = require('bluebird');
const AuthGW  = require('../lib/authgw');

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

  const claims = { subject: 'for the test' };

  let authgw = new AuthGW(['user', 'admin'], 'myapp', schema);

  authgw.createToken({userid: 1234, username: 'tyler'}, 'admin', 30, claims)
  .then(token => {
    t.assert(token, 'Token should exist');
    return authgw.verifyToken(token, { subject: 'for the test' });
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
  const claims = { subject: 'for the test' };
  let authgw = new AuthGW(['user', 'admin'], 'myapp', schema);

  try {
    let token = authgw.createTokenSync(
      {userid: 1234, username: 'tyler'}, 'admin', 30, claims
    );

    t.assert(token, 'Token should exist');

    let unwrapped = authgw.verifyTokenSync(token, { subject: 'for the test' });
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

  let runWith = (token, cb) => {
    let req = {
      headers: { 'x-access-token': token },
      get(header) { return this.headers[header]; }
    };

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

  let testCases = [];

  let successfulVerification = new Promise((resolve, reject) => {
    let userData = { userid: 1234, username: 'tyler' };
    let validToken = authgw.createTokenSync(userData, 'admin', 10);
    runWith(validToken, (err, req) => {
      t.comment('Valid Token Verification');
      if (err) reject(err);
      t.assert(req._tokenData, 'Data should have been injected into request');
      t.equal(req._tokenData.userid, userData.userid, 'Data should match the token');
      t.equal(req.userRole, 'admin', 'Should write the token role to req');
      resolve();
    });
  });
  testCases.push(successfulVerification);

  let invalidToken = new Promise((resolve, reject) => {
    runWith('notatoken', (err, req, res) => {
      t.comment('Invalid/Malformed Token');
      if (err) reject(err);

      t.equal(res.statusCode, 401, 'Error for malformed token should be 401');
      resolve();
    });
  });
  testCases.push(invalidToken);

  let emptyToken = new Promise((resolve, reject) => {
    runWith(null, (err, req) => {
      t.comment('Empty Token');
      if (err) reject(err);

      t.notok(req._tokenData, 'Token data should not be written');
      t.notok(req.userRole, 'Token role should not be written');
      resolve();
    });
  });
  testCases.push(emptyToken);

  Promise.all(testCases)
  .catch(err => t.error(err))
  .finally(() => t.end());
});

test('Data Injection Middleware', t => {
  let runWith = (schema, data, cb) => {
    const authgw = new AuthGW(['admin'], 'myapp', schema);
    let injectDataFn = AuthGW.Middleware.injectTokenDataExpress.call(authgw);
    let req = { userRole: 'admin', _tokenData: data };
    let res = {
      _status: 200,
      status(status) { this._status = status; return this; },
      sendStatus(status) { this._status = status; cb(null, req, res); },
      send() { cb(null, req, res); }
    };

    injectDataFn(req, res, err => cb(err, req, res));
  };

  let testCases = [];

  let stdRequest = new Promise((resolve, reject) => {
    let schema = [{name: 'userid', required: true}];
    runWith(schema, {userid: 'tyler'}, (err, req) => {
      t.comment('Valid Request - Required Only');
      if (err) return reject(err);

      t.equals(req.userid, 'tyler', 'UserID should be injected into request');
      resolve();
    });
  });
  testCases.push(stdRequest);

  let optionalData = new Promise((resolve, reject) => {
    let schema = [
      { name: 'userid', required: true }, { name: 'username', required: false }
    ];

    runWith(schema, { userid: 1234, username: 'tyler' }, (err, req) => {
      t.comment('Valid Request w/ Optional Val');
      if (err) return reject(err);

      t.equals(req.userid, 1234, 'UserID should be injected into request');
      t.equals(req.username, 'tyler', 'Optional key should be injected');
      resolve();
    });
  });
  testCases.push(optionalData);

  let missingData = new Promise(resolve => {
    runWith(
      [{name: 'reqOne', required: true}, {name: 'reqTwo', required: true}],
      { reqOne: true },
      (err, req, res) => {
        t.comment('Missing Required');
        t.equal(res._status, 401, 'Should send 401 status code');
        t.notok(req.reqOne, 'Should not write data that *was* given');
        resolve();
      }
    );
  });
  testCases.push(missingData);

  let noData = new Promise(resolve => {
    runWith([{name: 'userid', required: true}], null, err => {
      t.comment('No Data Passed');
      t.notok(err, 'Should not give an error');
      resolve();
    });
  });
  testCases.push(noData);

  let extraData = new Promise((resolve, reject) => {
    runWith(
      [{name: 'userid', required: true}], {userid: 'tyler', extra: true},
      (err, req) => {
        t.comment('Extra Data');
        if (err) return reject(err);

        t.ok(req.userid, 'Required key should be injected');
        t.notok(req.extra, 'Extra key should not be injected');
        resolve();
      }
    );
  });
  testCases.push(extraData);

  let missingOptional = new Promise(resolve => {
    let optionalSchema = [
      {name: 'userid', required: true}, {name: 'opt', required: false}
    ];

    runWith(optionalSchema, {userid: 'tyler'}, err => {
      t.comment('Missing Optional');
      t.assert(!err, 'Should not give error');
      resolve();
    });
  });
  testCases.push(missingOptional);

  let implicitOptional = new Promise(resolve => {
    let implicitOptSchema = [{name: 'userid', required: true}, {name: 'opt'}];

    runWith(implicitOptSchema, {userid: 'tyler'}, err => {
      t.comment('Implicit Optional');
      t.assert(!err, 'Should not give error');
      resolve();
    });
  });
  testCases.push(implicitOptional);

  Promise.all(testCases)
  .catch(err => t.error(err))
  .finally(() => t.end());
});
