'use strict';

const test = require('tape');
const RoleManager = require('../lib/role_manager');

test('Role Manager Restriction Middleware', t => {
  let runWith = (roles, curRole, allowedRoles, cb) => {
    let roleMgr = new RoleManager(roles);
    let roleMgrFn = roleMgr.restrictTo(allowedRoles);

    let req = { userRole: curRole };
    let res = {
      statusCode: null,
      sendHook: thisRes => cb(null, req, thisRes),
      sendStatus: function sendStatus(s) {
        this.statusCode = s;
        if (this.sendHook) this.sendHook(this);
        return this;
      }
    };

    roleMgrFn(req, res, err => cb(err, req, res));
  };
});
