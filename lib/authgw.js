/**
  AuthGateway
  @description Exposes an API to create a user token schema and registers
    the required middleware for verifying and unpacking user data into the req
    object, also exposes an API for generating user tokens with a given payload
  @author tylerFowler
**/

const crypto      = require('crypto');
const _           = require('underscore');
const Promise     = require('bluebird');
const JWT         = Promise.promisifyAll(require('jsonwebtoken'));
const RoleMgr     = require('./role_manager');
const AuthGWError = require('./errors');
const Flavors     = require('./flavors');

const { TokenTransport, TransportMethods } = require('./token_transport');

module.exports = exports = AuthGW;

// secondary components
let middleware = {};

// add exports
AuthGW.RoleManager = RoleMgr;
AuthGW.Middleware = middleware;
AuthGW.Error = require('./errors');
AuthGW.Flavors = require('./flavors');
AuthGW.TokenTransport = require('./token_transport').TokenTransport;
AuthGW.TransportMethods = require('./token_transport').TransportMethods;

/**
  @constructor AuthGW
  @desc Constructor function that creates a new gateway manager instance with
    the configured settings
  @param {string[]} roles list of all possible user roles from lowest
    access level to highest access level
  @param {string} authorityName serves as the JWT 'issuer' name
  @param {object[]} dataSchema defines the keys to r/w to/from tokens
  @param {object} opts
  @param {string} opts.tokenAlgo @default 'HS256'
  @param {string|Buffer} opts.tokenSecret @default 24 random bytes
  @param {number} opts.tokenExpiredCode @default 419 (Token Expired)
  @param {string} opts.flavor
  @param {object} opts.transport
  @param {string} opts.transport.method
  @param {string} opts.transport.key
  @param {object} opts.transport.injectionOptions
**/
function AuthGW(roles, authorityName, dataSchema, opts = {}) {
  if (!Array.isArray(roles)) roles = [roles];

  this.roles = roles;
  this.authorityName = authorityName;

  // if required is omitted default to false
  this.dataSchema = dataSchema.map(s => _.defaults(s, { required: false }));

  this.opts = Object.assign({
    tokenAlgo: 'HS256', // HMAC w/ SHA-256
    tokenSecret: crypto.randomBytes(24).toString('hex'),
    tokenExpiredCode: 419,
    flavor: Flavors.EXPRESSJS
  }, opts, {
    transport: Object.assign({
      method: TransportMethods.HEADER,
      key: 'x-access-token'
    }, opts.transport)
  });

  const { flavor, transport } = this.opts;
  this.tokenTransport = new TokenTransport(
    flavor, transport.method, transport.key, transport.injectionOptions
  );

  this.RoleManager = new RoleMgr(roles);
}

/**
  @name AuthGW#createToken
  @desc Creates a new auth token with the given role & data
  @param {object} data written to the token, needs keys required by schema
  @param {string} role one of the roles given to this authgw instance
  @param {number} expiry time to live of the token in minutes
  @param {object} claims arbitrary claims to be passed to JWT
  @returns {Promise<String>} token containing the raw encrypted token
  @returns {Promise<InvalidRoleError>} if the given role is not listed
**/
AuthGW.prototype.createToken = function createToken(data, role, expiry, claims) {
  return Promise.attempt(() => {
    if (!_.contains(this.roles, role))
      throw new AuthGWError.InvalidRoleError(role);
  })
  .then(() =>
    new Promise((resolve, reject) => {
      const opts = Object.assign({
        algorithm: this.opts.tokenAlgo,
        expiresIn: expiry * 60,
        issuer: this.authorityName
      }, claims || {});

      JWT.sign({data, role}, this.opts.tokenSecret, opts, (err, token) => {
        if (err) reject(err);
        else resolve(token);
      });
    })
  );
};

/**
  @name AuthGW#createTokenSync
  @desc Sync version of create token
  @see AutghGW#createToken
  @returns {string} containing the encrypted token
  @throws InvalidRoleError if the given role is not listed
**/
AuthGW.prototype.createTokenSync = function createToken(data, role, expiry, claims) {
  if (!_.contains(this.roles, role))
    throw new AutghGwError.InvalidRoleError(role);

  const opts = Object.assign({
    algorithm: this.opts.tokenAlgo,
    expiresIn: expiry * 60,
    issuer: this.authorityName
  }, claims || {});

  return JWT.sign({ data, role }, this.opts.tokenSecret, opts);
};

/**
  @name AuthGW#verifyToken
  @desc Verifies that a given token is valid, unexpired, and trusted
  @param {string} token is the encrypted auth token
  @param {object} claims are used in token validation
  @returns {Promise<Object>} object containing the token's payload data if valid
**/
AuthGW.prototype.verifyToken = function verifyToken(token, claims) {
  const opts = Object.assign({ issuer: this.authorityName }, claims || {});
  return JWT.verifyAsync(token, this.opts.tokenSecret, opts);
};

/**
  @name AuthGW#verifyTokenSync
  @desc Sync version of verify token
  @see AuthGW#verifyToken
  @returns {object} contains the token's payload data if valid
**/
AuthGW.prototype.verifyTokenSync = function verifyToken(token, claims) {
  const opts = Object.assign({ issuer: this.authorityName }, claims || {});
  return JWT.verify(token, this.opts.tokenSecret, opts);
};

/**
  @name AuthGW#injectToken
  @desc injects the given token into the response object using the token
    transport associated with the instance
  @param {object} response
  @param {string} token the token to inject
**/
AuthGW.prototype.injectToken = function inejctToken(response, token) {
  this.tokenTransport.injectToken(response, token);
};

/**
  @name AuthGW#middleware
  @desc Factory that creates the two Express middleware functions necessary
    for writing the data we need & verifying the auth token
  @param {object} verifClaims extra claims that will be passed to verification
  @returns [ verifyTokenFn(req,res,next), injectDataFn(req,res,next) ]
**/
AuthGW.prototype.middleware = function createExpressMiddleware(verifClaims) {
  switch (this.opts.flavor) {
  case Flavors.EXPRESSJS:
    return [
      middleware.verifyTokenExpress.call(this, verifClaims),
      middleware.injectTokenDataExpress.call(this)
    ];
  default:
    throw new InvalidFlavorError(this.opts.flavor, 'middleware');
  }
};

/**
  @name Middleware#verifyToken
  @desc ExpressJS flavor of the verify token middleware, verifies the auth token
    Note that if no auth token was given we *will* move along, but without
    writing any data to the request object
  @param {object} verifClaims
  @returns {function} verifyToken
  @returns 401 if the given token is invalid or expired
**/
middleware.verifyTokenExpress = function verifyToken(verifClaims) {
  return (req, res, next) => {
    const authToken = this.tokenTransport.extractToken(req);

    // if there's no token just don't inject the user data
    if (!authToken) return next();

    this.verifyToken(authToken, verifClaims || {})
    .then(tokenData => {
      req._tokenData = tokenData.data;
      req.userRole = tokenData.role;
      next();
    })

    // NOTE: it is **vitally** important that the client does *not* send a
    // another request with this token after receiving this error code
    // (say to prompt signin) or else this will be sent again,
    // resulting in an infinite loop
    .catch(
      JWT.TokenExpiredError, () => res.sendStatus(this.opts.tokenExpiredCode)
    )

    // token is malformed or otherwise unreadable
    .catch(JWT.JsonWebTokenError, () =>
      res.status(401).send('Invalid authorization token')
    )

    // general error, send 500
    .catch(err => next(err));
  };
};

/**
  @name Middleware#injectTokenData
  @desc ExpressJS flavor of the injection middleware, injects the decoded
    auth token's data into the req object, returning an error if a required
    field from the schema is missing
  @returns {function} injectTokenData
  @returns 401 if the given token is missing required data
**/
middleware.injectTokenDataExpress = function injectTokenData() {
  return (req, res, next) => {
    var err;
    if (!req._tokenData) return next();

    _.chain(req._tokenData)
    .pick(_.pluck(this.dataSchema, 'name'))
    .tap(filtered => {
      let result = validateSchema(filtered, this.dataSchema);
      if (!result.valid)
        err = new Error(`Required item ${result.missingKey} is missing`);
    })
    .each((v, k) => { if (err) return; req[k] = v; });

    if (err) res.status(401).send('Invalid token data');
    else next();
  };
};

/** Utility Functions **/
/**
  @name validateSchema
  @desc Validates that the given data fulfills the given schema
  @param {object} data to validate
  @param {object} schema AuthGW schema to validate against
  @returns { valid, missingKey }
**/
function validateSchema(data, schema) {
  let missing = _.find(schema, s => s.required && !_.has(data, s.name));

  if (missing)
    return { valid: false, missingKey: missing.name };

  return { valid: true };
}
