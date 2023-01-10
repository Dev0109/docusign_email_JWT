var Scope_SIGNATURE = require('./oauth/Scope').SIGNATURE;
var Scope_EXTENDED = require('./oauth/Scope').EXTENDED;
var Scope_IMPERSONATION = require('./oauth/Scope').IMPERSONATION;
var Scope_COMPANY_WRITE = require('./oauth/Scope').COMPANY_WRITE;
var Scope_COMPANY_READ = require('./oauth/Scope').COMPANY_READ;
var Scope_MONITOR_WRITE = require('./oauth/Scope').MONITOR_WRITE;
var Scope_MONITOR_READ = require('./oauth/Scope').MONITOR_READ;
var Scope_ORGANIZATION_READ = require('./oauth/Scope').ORGANIZATION_READ;
var Scope_ORGANIZATION_WRITE = require('./oauth/Scope').ORGANIZATION_WRITE;
var Scope_USER_WRITE = require('./oauth/Scope').USER_WRITE;
var Scope_USER_READ = require('./oauth/Scope').USER_READ;

var PRODUCTION_OAUTH_BASE_PATH = require('./oauth/BasePath').PRODUCTION;
var DEMO_OAUTH_BASE_PATH = require('./oauth/BasePath').DEMO;
var STAGE_OAUTH_BASE_PATH = require('./oauth/BasePath').STAGE;
var CODE = require('./oauth/ResponseType').CODE;
var TOKEN = require('./oauth/ResponseType').TOKEN;
var UserInfo = require('./oauth/UserInfo');
var OAuthToken = require('./oauth/OAuthToken');

module.exports = {
  Scope: {
    SIGNATURE: Scope_SIGNATURE,
    EXTENDED: Scope_EXTENDED,
    IMPERSONATION: Scope_IMPERSONATION,
    COMPANY_WRITE: Scope_COMPANY_WRITE,
    COMPANY_READ: Scope_COMPANY_READ,
    MONITOR_WRITE: Scope_MONITOR_WRITE,
    MONITOR_READ: Scope_MONITOR_READ,
    ORGANIZATION_READ: Scope_ORGANIZATION_READ,
    ORGANIZATION_WRITE: Scope_ORGANIZATION_WRITE,
    USER_WRITE: Scope_USER_WRITE,
    USER_READ: Scope_USER_READ
  },
  ResponseType: {
    CODE: CODE,
    TOKEN: TOKEN,
  },
  BasePath: {
    PRODUCTION: PRODUCTION_OAUTH_BASE_PATH,
    STAGE: STAGE_OAUTH_BASE_PATH,
    DEMO: DEMO_OAUTH_BASE_PATH,
  },
  UserInfo: UserInfo,
  OAuthToken: OAuthToken
};

Object.freeze(module.exports.Scope);
Object.freeze(module.exports.ResponseType);
Object.freeze(module.exports.BasePath);
