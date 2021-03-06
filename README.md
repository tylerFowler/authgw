AuthGateway
===============

Exposes an API to create user auth tokens based on the [JWT](jwt.io) spec and provides middleware plugins for user role access management on a route-by-route basis and for validating an auth token generated by this library.

- currently only supports Express but could easily be extended for other formats

# Usage

```js
  const AuthGW = require('authgw');
  const app    = require('express')();
  const { TransportMethods, Flavors } = require('authgw');

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
      flavor: Flavors.EXPRESSJS, // the flavor of middleware to use, options found in lib/flavors.js
      tokenSecret: '<randomly generated>', // the secret key used to encrypt the tokens
      tokenExpiredCode: 419 // HTTP code to return if token is expired, 419 Session Timeout (unofficial) is the default

      // the transport is a wrapper around the method used to get the token
      // from a request, as well as putting the token into responses using
      // convenience methods
      transport: {
        method: TransportMethods.HEADER, // use headers for transporting tokens, options found in the TokenTransports enumeration
        key: 'x-access-token' // the 'key' to use when retrieving the token, in this case a header name
      }
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
  // or
  app.get('/robots.txt', RoleMgr.restrictTo('*'), (req, res) => { ... });

  // create an auth token
  app.get('/signin', RoleMgr.allowAll(), (req, res) => {
    // get the data specified by the authgw configured data scheme
    let userData = { userid: req.body.userid, username: req.body.username };

    authgw.createToken(
      // data that is bundled w/ the token, will be injected into req when this
      // token goes through the middleware during a request
      userData,

      // role given to the token holder
      'user',

      // expiry of this token in minutes, expired tokens will be rejected by
      // the token verification middleware
      24 * 60
    )
    // inject the token into the response in any way you see fit
    .then(mytoken => res.send(mytoken))
    // or, use the authgw instance to inject the token according to the
    // rules set by the token transport settings
    .then(mytoken => authgw.injectToken(res, mytoken));
  });
```

# Considerations
## Beware the dreaded invalidation loop
It is **vitally** important that the client does **not** send another request with a token known to be invalid (i.e. your client has received the status code indicating session expiration or invalidation), or else the middleware will simply continue to send the error code – resulting in an infinite loop.

## Randomly generated secrets
By default this library will make your JWT secret a random hex value generated from 24 random bytes (using Node's `crypto` library). This means that whenever your application restarts all tokens generated before the restart will now be invalid. Worse, if you use a round robin technique with multiple Node processes then the tokens will *not* be compatible between the instances. So it's highly recommended that you override this setting.

# TODO:
- make docs better, specifically add API docs
- allow middleware to be configured to use extra claims as validation
- remove dependency on underscore
- remove dependency on Bluebird, use native Promises & allow it to be pluggable
