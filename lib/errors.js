/**
  AuthGW Custom Errors
  @author tylerFowler
**/

/**
  @class InvalidRoleError @extends Error
  @desc Thrown when a role is given that is not in the list of roles
  @param { String } invalidRole
**/
class InvalidRoleError extends Error {
  constructor(invalidRole) {
    super();
    this.name = 'InvalidRoleError';
    this.message = `${invalidRole} is not a valid role`;
  }
}
exports.InvalidRoleError = InvalidRoleError;
