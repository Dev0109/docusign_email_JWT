var SIGNATURE = 'signature';
var EXTENDED = 'extended';
var IMPERSONATION = 'impersonation';
var COMPANY_WRITE = 'dtr.company.write';
var COMPANY_READ = 'dtr.company.read';
var MONITOR_WRITE = 'dtr.orgadmin.write';
var MONITOR_READ = 'dtr.orgadmin.read';
var ORGANIZATION_READ = 'organization_read';
var ORGANIZATION_WRITE = 'organization_write';
var USER_READ = 'user_read';
var USER_WRITE = 'user_write';

module.exports = {
  SIGNATURE: SIGNATURE,
  EXTENDED: EXTENDED,
  IMPERSONATION: IMPERSONATION,
  COMPANY_WRITE: COMPANY_WRITE,
  COMPANY_READ: COMPANY_READ,
  MONITOR_WRITE: MONITOR_WRITE,
  MONITOR_READ: MONITOR_READ,
  ORGANIZATION_READ: ORGANIZATION_READ,
  ORGANIZATION_WRITE: ORGANIZATION_WRITE,
  USER_READ: USER_READ,
  USER_WRITE: USER_WRITE,
};

Object.freeze(module.exports);
