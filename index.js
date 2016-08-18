module.exports     = require('./lib/authgw');
module.Middleware  = require('./lib/authgw').Middleware;
module.RoleManager = require('./lib/role_manager');
module.Error       = require('./lib/errors');
module.Flavors     = require('./lib/flavors');
module.TokenTransport = require('./lib/token_transport').TokenTransport;
module.TransportMethods = require('./lib/token_transport').TransportMethods;
