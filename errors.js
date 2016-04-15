/**
  AuthGW Custom Errors
  @author tylerFowler
**/

/**
  @name InvalidRoleError
  @desc Thrown when a role is given that is not in the list of roles
  @param { String } invalidRole
**/
function InvalidRoleError(invalidRole) {
  this.name = 'InvalidRoleError';
  this.message = `${invalidRole} is not a valid role`;
  this.stack = (new Error()).stack;
}
InvalidRoleError.prototype = Object.create(Error.prototype);
InvalidRoleError.prototype.constructor = InvalidRoleError;
exports.InvalidRoleError = InvalidRoleError;
