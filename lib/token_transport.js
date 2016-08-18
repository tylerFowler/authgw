/**
  Token Transports
  @description a collection of different token transports in different
    frameworks, exported as a single abstracted API
  @author tylerFowler
**/

const {
  InvalidFlavorError,
  InvalidTransportMethodError
} = require('./errors');

const flavors = require('./flavors');
const transportMethods = {
  HEADER: 'header-transport',
  COOKIE: 'cookie-transport'
};
exports.TransportMethods = transportMethods;

const transports = {
  [flavors.EXPRESSJS]: {
    [transportMethods.HEADER]: {
      extract(req) { return req.get(this.key); },
      inject(res, token) { res.set(this.key, token); }
    },
    [transportMethods.COOKIE]: {
      extract(req) { return req.cookies[this.key]; },
      inject(res, token) { res.cookie(this.key, token, this.opts); }
    }
  }
};
console.log('Tports: ', transports);

/**
  @name TokenTransport
  @desc creates a new TokenTransport with the given method & flavor
  @param {string} flavor typically the framework being used
  @param {string} transportMethod the method used to carry the token
  @param {string} key the key used to retrieve tokens
  @param {object} injectOpts arbitrary options passed to the injection method
  @returns {object} transport
  @throws {InvalidFlavorError} error
  @throws {InvalidTransportMethodError} error
**/
function TokenTransport(flavor, transportMethod, key, injectOpts = {}) {
  this.key = key;
  this.opts = injectOpts;

  if (!Object.keys(flavors)
    .map(k => flavors[k]).find(f => f === flavor)
  ) throw new InvalidFlavorError(flavor, 'transport');
  this.flavor = flavor;

  if (!Object.keys(transportMethods)
    .map(k => transportMethods[k]).find(m => m === transportMethod)
  ) throw new InvalidTransportMethodError(transportMethod);
  this.transportMethod = transportMethod;
}

TokenTransport.prototype.extractToken = function extractToken(req) {
  return transports[this.flavor][this.transportMethod].extract.call(this, req);
};

TokenTransport.prototype.injectToken = function injectToken(res, token) {
  return transports[this.flavor][this.transportMethod].inject.call(this, res, token);
};

exports.TokenTransport = TokenTransport;
