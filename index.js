/**
  AuthGateway Middleware
  @description Exposes an API to create a user token schema and registers
    the required middleware for verifying and unpacking user data into the req
    object, also exposes an API for generating user tokens with a given payload
  @author tylerFowler
**/
'use strict';

const crypto  = require('crypto');
const _       = require('underscore');
const Promise = require('bluebird');
const JWT     = Promise.promisifyAll(require('jsonwebtoken'));
const RoleMgr = require('./role_manager');

module.exports = exports = AuthGW;

// secondary components
let middleware = exports.Middleware = {};

/**
  @constructor AuthGW
  @desc Constructor function that creates a new gateway manager instance with
    the configured settings
  @param { String[] } roles - list of all possible user roles from lowest
    access level to highest access level :optional
  @param { String } authorityName - serves as the JWT 'issuer' name
  @param { Object[] } dataSchema - defines the keys to r/w to/from tokens
  @param { Object } opts
  @returns AuthGW instance
**/
function AuthGW(roles, authorityName, dataSchema, opts) {
  if (!Array.isArray(roles)) roles = [roles];

  this.roles = roles;
  this.authorityName = authorityName;

  // if required is omitted default to false
  this.dataSchema = dataSchema.map(s => _.defaults(s, { required: false }));

  this.opts = Object.assign({
    tokenHeader: 'x-access-token',
    tokenSecret: crypto.randomBytes(24).toString('hex'),
    tokenExpiredCode: 419
  }, opts);

  this.RoleManager = new RoleMgr(roles);
}

/**
  @name AuthGW#createToken
  @desc Creates a new auth token with the given role & data
  @param { Object } data written to the token, must have keys required by schema
  @param { String } role must be one of the roles given to this authgw instance
  @param { Number } expiry time of the token in minutes
  @returns { String } token contains the raw, encrypted token
  @throws InvalidRoleError if the given role is not listed
**/
AuthGw.prototype.createToken = function createToken(data, role, expiry) {
  if (!_.contains(this.roles, role))
    throw new AuthGWError.InvalidRoleError(role);

  return JWT.sign(
    { data, role },
    this.opts.tokenSecret,
    {
      algorithm: 'HS256', // HMAC w/ SHA-256
      expiresIn: expiry * 60,
      issuer: this.authorityName
    }
  );
};

/**
  @name AuthGW#verifyAuthToken
  @desc Verifies that a given token is valid, unexpired, and trusted
  @param { String } token is the encrypted auth token
  @returns Promise<Object> contains the token's data
**/
AuthGW.prototype.verifyToken = function verifyToken(token) {
  return JWT
  .verifyAsync(token, this.opts.tokenSecret, { issuer: this.authorityName });
};

/**
  @name AuthGW#middleware
  @desc Factory that creates the two Express middleware functions necessary
    for writing the data we need & verifying the auth token
  @returns [ verifyTokenFn(req,res,next), injectDataFn(req,res,next) ]
**/
AuthGW.prototype.middleware = function createMiddleware() {
  return [
    middleware.verifyTokenExpress.call(this),
    middleware.injectTokenDataExpress.call(this)
  ];
};

/**
  @name Middleware#verifyToken
  @desc ExpressJS flavor of the verify token middleware, verifies the auth token
    Note that if no auth token was given we *will* move along, but without
    writing any data to the request object
  @returns { Function } verifyToken
  @returns 401 if the given token is invalid or expired
**/
middleware.verifyTokenExpress = function verifyToken() {
  return (req, res, next) => {
    const authToken = req.headers[this.opts.tokenHeader];

    // if there's no token just don't inject the user data
    if (!authToken) return next();

    this.verifyToken(authToken)
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
    .catch(() => res.sendStatus(500));
  };
};

/**
  @name Middleware#injectTokenData
  @desc ExpressJS flavor of the injection middleware, injects the decoded
    auth token's data into the req object, returning an error if a required
    field from the schema is missing
  @returns { Function } injectTokenData
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
    .each((v, k) => req[k] = v);

    if (err) next(err);
    else next();
  };
};

/** Utility Functions **/
/**
  @name validateSchema
  @desc Validates that the given data fulfills the given schema
  @param { Object } data to validate
  @param { Object } AuthGW schema to validate against
  @returns { valid, missingKey }
**/
function validateSchema(data, schema) {
  let missing = _.find(schema, s => s.required && !_.has(data, s.name));

  if (missing)
    return { valid: false, missingKey: missing.name };

  return { valid: true };
}
