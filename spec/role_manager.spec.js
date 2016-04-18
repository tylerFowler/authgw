'use strict';

const test        = require('tape');
const Promise     = require('bluebird');
const RoleManager = require('../lib/role_manager');

test('Role Manager Restriction Middleware', t => {
  let runWith = (roles, curRole, allowedRoles, cb) => {
    let roleMgr = new RoleManager(roles);
    let roleMgrFn = roleMgr.restrictTo(allowedRoles);

    let req = { userRole: curRole };
    let res = {
      statusCode: null,
      sendHook: thisRes => cb(thisRes),
      sendStatus: function sendStatus(s) {
        this.statusCode = s;
        if (this.sendHook) this.sendHook(this);
        return this;
      }
    };

    roleMgrFn(req, res, () => cb(res));
  };

  let testCases = [];

  let allowedUser = new Promise(resolve => {
    runWith(['user', 'admin'], 'user', ['user', 'admin'], res => {
      t.comment('Allowed User');
      t.notok(res.statusCode, 'Should pass through');
      resolve();
    });
  });
  testCases.push(allowedUser);

  let notAllowed = new Promise(resolve => {
    runWith(['admin'], 'user', ['admin'], res => {
      t.comment('Not Allowed');
      t.equals(res.statusCode, 403, 'Should return 403 Forbidden');
      resolve();
    });
  });
  testCases.push(notAllowed);

  let noArray = new Promise(resolve => {
    runWith(['admin'], 'admin', 'admin', res => {
      t.comment('Arrayless Value');
      t.notok(res.statusCode, 'Should not give an error');
      resolve();
    });
  });
  testCases.push(noArray);

  let allowAll = new Promise(resolve => {
    t.comment('Wildcard Matching');
    let wildcardArgs = (role, cb) => [['user', 'admin'], role, '*', cb];
    let finished = false;

    runWith.apply(
      null, wildcardArgs('user', res => {
        t.notok(res.statusCode, 'Should pass through for user role');

        if (finished) resolve();
        else finished = true;
      })
    );

    runWith.apply(
      null, wildcardArgs('admin', res => {
        t.notok(res.statusCode, 'Should pass through for admin role');

        if (finished) resolve();
        else finished = true;
      })
    );
  });
  testCases.push(allowAll);

  let noReqRole = new Promise(resolve => {
    runWith(['admin'], null, ['admin'], res => {
      t.comment('No Request Role');
      t.equals(res.statusCode, 401, 'Should return 401 Unauthorized');
      resolve();
    });
  });
  testCases.push(noReqRole);

  Promise.all(testCases)
  .catch(err => t.error(err))
  .finally(() => t.end());
});

test('Custom Role Groupings', t => {
  let roleMgr = new RoleManager(['guest', 'user', 'restricted', 'admin']);

  try {
    roleMgr.addRoleGrouping('users', ['user', 'restricted', 'admin']);
    t.assert(roleMgr.allowUsers, 'Should add an allowUsers method');
  } catch (err) { t.error(err); }

  try {
    roleMgr.addRoleGrouping('guest', 'guest');
    t.assert(roleMgr.allowGuest, 'Should accept nonarray values');
  } catch (err) { t.error(err); }

  t.throws(
    () => roleMgr.addRoleGrouping('invalid', [ 'user86', 'notarole', 'admin' ]),
    'Should throw an error for invalid roles'
  );

  t.throws(
    () => roleMgr.addRoleGrouping('a', 'notarole'),
    'Should throw an error for a single invalid role'
  );

  t.end();
});

test('Get Roles from Minimum', t => {
  let roleMgr = new RoleManager(['guest', 'user', 'admin']);

  t.deepEquals(
    roleMgr.getRolesFromMinimum('user'),
    [ 'user', 'admin' ],
    'Should return the roles above the given one, inclusive'
  );

  t.deepEquals(
    roleMgr.getRolesFromMinimum('admin'),
    [ 'admin' ],
    'Should return the last role if the last role is provided'
  );

  t.throws(
    () => roleMgr.getRolesFromMinimum('notarole'),
    'Should throw if given role is not valid'
  );

  t.end();
});
