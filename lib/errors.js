/**
  AuthGW Custom Errors
  @author tylerFowler
**/

/**
  @class InvalidRoleError @extends Error
  @desc thrown when a role is given that is not in the list of roles
  @param {string} invalidRole
**/
class InvalidRoleError extends Error {
  constructor(invalidRole) {
    super();
    this.name = 'InvalidRoleError';
    this.message = `${invalidRole} is not a valid role`;
  }
} exports.InvalidRoleError = InvalidRoleError;

/**
  @class InvalidFlavorError @extends Error
  @desc thrown when an invalid middleware/transport flavor is given
  @param {string} invalidFlavor
  @param {string} ctxt used to identify where the invalid flavor was used
**/
class InvalidFlavorError extends Error {
  constructor(invalidFlavor, ctxt) {
    super();
    this.name = 'InvalidFlavorError';
    this.message = `${invalidFlavor} is not a valid ${ctxt} flavor`;
  }
} exports.InvalidFlavorError = InvalidFlavorError;

/**
  @class InvalidTransportMethodError @extends Error
  @desc thrown when an invalid transport method is given
  @param {string} invalidMethod
**/
class InvalidTransportMethodError extends Error {
  constructor(invalidMethod) {
    super();
    this.name = 'InvalidTransportMethodError';
    this.message = `${invalidMethod} is not a valid transport method`;
  }
} exports.InvalidTransportMethodError = InvalidTransportMethodError;
