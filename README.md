AuthGateway
===============

Exposes an API to create user auth tokens based on the [JWT](jwt.io) spec and provides middleware plugins* for user role access management on a route-by-route basis and for validating an auth token generated by this library.

# Usage

```js
  const AuthGW = require('authgw');
  const app    = require('express')();

  // set AuthGW configuration, library is stateful so only do this once
  let authgw = new AuthGW(
    // list of user roles, or null/empty if not using roles
    // it is important that the roles are ordered from lowest access level
    // to highest access level
    [ 'guest', 'user', 'admin' ],

    // issuer name, used to validate that a token came from a trusted source
    'myapp',

    // data schema, defines the data for what's written as into a token's
    // payload, required keys throw errors during validation when falsy
    [
      { name: "userid",   required: true  },
      { name: "username", required: false }
    ],

    // general options, defaults are shown
    {
      tokenHeader: 'x-access-token', // the header to read & write an auth token
      tokenSecret: '<randomly generated>', // the secret key used to encrypt the tokens
      tokenExpiredCode: 419 // HTTP code to return if token is expired, 419 Session Timeout (unofficial) is the default
    }
  );

  // tell our Express app to use the middleware generated by our configuration
  // this middleware will return 401 errors if a request contains an invalid
  // or expired auth token, otherwise it will write the data fields provided by
  // the data schema to the request object, returning 401 if the token does not
  // contain a data field marked "required" by the schema
  app.use(authgw.middleware());

  // we can use the Role Manager to lock down routes to a given list of roles,
  // these are handled on a route-by-route basis and it's highly recommended
  // to place the middleware declaration directly before the route definition,
  // though they can be declared anywhere as long as it's before the route def
  const RoleMgr = authgw.RoleManager;

  // only allow Admin users
  app.get('/supersecret', RoleMgr.restrictTo('admin'), (req, res) => { ... });

  // users and admins
  app.post('/myroute', RoleMgr.restrictTo(['user', 'admin']), (req, res) => { ... });

  // as the role lists get long and repetitive it's a good idea to start creating
  // named role groups using RoleManager#addRoleGrouping
  RoleMgr.addRoleGrouping('users', [ 'user', 'admin' ]);

  // RoleMgr.allowUsers() is now equiv. to RoleMgr.restrictTo(['user', 'admin'])
  app.get('/userstuff', RoleMgr.allowUsers(), (req, res) => { ... });

  // errbody
  app.get('/robots.txt', RoleMgr.allowAll(), (req, res) => { ... });

  // create an auth token
  app.get('/signin', RoleMgr.allowAll(), (req, res) => {
    // get the data specified by the authgw configured data scheme
    let userData = { userid: req.body.userid, username: req.body.username };

    let authToken = authgw.createToken(
      // data that is bundled w/ the token, will be injected into req when this
      // token goes through the middleware during a request
      userData,

      // role given to the token holder
      'user',

      // expiry of this token in minutes, expired tokens will be rejected by
      // the token verification middleware
      24 * 60
    );
  });
```
