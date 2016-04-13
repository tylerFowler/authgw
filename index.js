/**
  AuthGateway Middleware
  @description Exposes an API to create a user token schema and registers
    the required middleware for verifying and unpacking user data into the req
    object, also exposes an API for generating user tokens with a given payload
  @author tylerFowler
**/
'use strict';

module.exports = exports = AuthGW;

/**
  @constructor AuthGW
  @desc Factory function that creates a new gateway manager instance with
    the configured settings
  @param { String[] } roles - list of all possible user roles from lowest
    access level to highest access level
  @param { String } authorityName - serves as the JWT 'issuer' name
  @param { Object } dataSchema - defines the keys you expect to write to tokens
  @returns AuthGW instance
**/
let AuthGW = module.exports = exports =
function AuthGW(roles, authorityName, dataSchema) {
  if (!Array.isArray(roles)) roles = [roles];
};
