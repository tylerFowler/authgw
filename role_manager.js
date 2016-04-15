/**
  Role Manager Middleware
  @description Provides middleware that can be inserted into a router that
    serves as an access level gateway for deciding if a user can retrieve
    the given content. Must be run *after* the Verify Authtoken middleware
    so that the current user's role is set properly.
  @author tylerFowler
**/
'use strict';

const _            = require('underscore');
const AuthGWError  = require('errors');

// character that represents 'All' roles
const RoleWildcard = '*';

module.exports = exports = RoleManager;

function RoleManager(roles) {
  // be sure to add the wildcard to the beginning of the roles list
  this.roles = _.union(RoleWildcard, roles);
}

/**
  @name RoleManager#restrictTo
  @desc Middleware that restricts access to a route to the given role list
    Note that this must be run *after* the verify token middleware or any
    middleware that sets the 'userRole' key on the request object
  @param { String[]|String } allowedRoles
  @returns 401 Unauthorized if the user role key is not present
  @returns 403 Forbidden if the request's role isn't in the allowd roles list
**/
RoleManager.prototype.restrictTo = function restrictTo(allowedRoles) {
  restrictToExpress.call(this, allowedRoles);
};

let restrictToExpress = function restrictTo(allowedRoles) {
  return (req, res, next) => {
    if (!Array.isArray(allowedRoles)) allowedRoles = [allowedRoles];

    if (_.contains(allowedRoles, RoleWildcard)) return next();
    if (!req.userRole) return res.sendStatus(401);
    if (_.contains(allowedRoles, req.userRole)) return next();

    res.sendStatus(403);
  };
};

/**
  RoleManager#getRolesFromMinimum
  @desc Gets the list of every role above & including the given min role
    Note that this assumes that the list of roles is lowest to highest priority
  @param { String } minRole => a value in the role list, case insensitive
  @returns { String[] }
  @throws InvalidRoleError if minRole is not a value in roles
**/
RoleManager.prototype.getRolesFromMinimum =
function getRolesFromMinimum(minRole) {
  if (!_.contains(this.roles, minRole))
    throw new AuthGWError.InvalidRoleError(minRole);

  return _.chain(this.roles)
  .map(r => r.toLowerCase())
  .last(roles.length - this.roles.findIndex(r => r === minRole.toLowerCase()))
  .value();
};
