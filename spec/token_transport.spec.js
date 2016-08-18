const test = require('tape');
const flavors = require('../lib/flavors');
const { TokenTransport, TransportMethods } = require('../lib/token_transport');

const expressReqMock = {
  headers: {},
  cookies: {},
  get(header) { return this.headers[header]; },
  set(header, value) { this.headers[header] = value; },
  cookie(name, val, opts) {
    this.cookies[name] = { value: val, options: opts };
  }
};

test('TokenTransport -> ExpressJS', st => {
  st.test('Headers', t => {
    const key = 'x-access-token';
    const transport = new TokenTransport(
      flavors.EXPRESSJS, TransportMethods.HEADER, key
    );

    const req = Object.assign({}, expressReqMock);
    transport.injectToken(req, 'some-token');

    t.equal(req.headers[key], 'some-token', 'writes the token to the header');

    const token = transport.extractToken(req);
    t.equal(token, 'some-token', 'extracts the token from the header');
    t.end();
  });

  st.test('Cookies', t => {
    const key = 'accesstoken';
    const transport = new TokenTransport(
      flavors.EXPRESSJS, TransportMethods.COOKIE,
      key, { domain: 'somedomain.com' }
    );

    const req = Object.assign({}, expressReqMock);
    transport.injectToken(req, 'some-token');

    const cookie = req.cookies[key];
    t.equal(cookie.value, 'some-token', 'writes the token to the cookie');
    t.equal(cookie.options.domain, 'somedomain.com', 'applies options');
    t.notEqual(req.headers[key], 'some-token', "doesn't write a header");

    const token = transport.extractToken(req).value;
    t.equal(token, 'some-token', 'extracts the token from the cookie');
    t.end();
  });

  st.end();
});
