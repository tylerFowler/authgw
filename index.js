/**
  AuthGateway Middleware
  @description Exposes an API to create a user token schema and registers
    the required middleware for verifying and unpacking user data into the req
    object, also exposes an API for generating user tokens with a given payload
  @author tylerFowler
**/
'use strict';

const crypto  = require('crypto');
const Promise = require('bluebird');
const JWT     = Promise.promisifyAll(require('jsonwebtoken'));

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
  @param { Object } dataSchema - defines the keys you expect to write to tokens
  @param { Object } opts
  @returns AuthGW instance
**/
module.exports = exports = AuthGW;
function AuthGW(roles, authorityName, dataSchema, opts) {
  if (!Array.isArray(roles)) roles = [roles];

  this.roles = roles;
  this.authorityName = authorityName;
  this.dataSchema = dataSchema; // TODO: could we give functions to be evaluated?
  this.opts = Object.assign({
    tokenHeader: 'x-access-token',
    tokenSecret: crypto.randomBytes(24).toString('hex'),
    tokenExpiredCode: 419
  }, opts);
}

/**
  @name AuthGW#verifyAuthToken
  @desc Verifies that a given token is valid, unexpired, and trusted
  @param { String } token is the encrypted auth token
  @returns Promise<Object> contains the token's data
**/
AuthGW.prototype.verifyAuthToken = function verifyAuthtoken(token) {
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

    this.verifyAuthToken(authToken)
    .then(tokenData => {
      req._tokenData = tokenData;
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
    const data = req._tokenData;
    // TODO:
    // - validate data fields match schema, throw away anything extra
    // - write schema fields into request object
  };
};
