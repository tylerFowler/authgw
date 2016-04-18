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
const AuthGWError  = require('./errors');

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
  return restrictToExpress.call(this, allowedRoles);
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
  @name RoleManager#addRoleGrouping
  @desc Adds a new shorthand method to this instance for restricting access
    to the given role group, will be named like 'allow${name}' in camel case
  @param { String } groupName => name of the role group, used in method name
  @param { String[] } roleGroup => roles to group together, must be valid roles
  @throws InvalidRoleError if a role in the group is invalid
**/
RoleManager.prototype.addRoleGrouping =
function addRoleGrouping(groupName, roleGroup) {
  if (!Array.isArray(roleGroup)) roleGroup = [roleGroup];

  let roleDiff = _.difference(roleGroup, this.roles);
  if (roleDiff.length > 0)
    throw new AuthGWError.InvalidRoleError(roleDiff);

  let camelName = groupName[0].toUpperCase + _.rest(groupName).join('');

  this[`allow${camelName}`] = () => this.restrictTo(roleGroup);
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
