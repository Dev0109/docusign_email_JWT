#!/usr/bin/env node

const express = require('express');
const session = require('express-session');  // https://github.com/expressjs/session
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const MemoryStore = require('memorystore')(session); // https://github.com/roccomuso/memorystore
const path = require('path');
const DSAuthCodeGrant = require('./lib/DSAuthCodeGrant');
const DsJwtAuth = require('./lib/DSJwtAuth');
const passport = require('passport');
const DocusignStrategy = require('passport-docusign');
const docOptions = require('./config/documentOptions.json');
const docNames = require('./config/documentNames.json');
const dsConfig = require('./config/index.js').config;
const commonControllers = require('./lib/commonControllers');
const flash = require('express-flash');
const helmet = require('helmet'); // https://expressjs.com/en/advanced/best-practice-security.html
const moment = require('moment');
const csrf = require('csurf'); // https://www.npmjs.com/package/csurf
const examplesApi = require('./config/examplesAPI.json');
const { getManifest } = require('./lib/manifestService')

const eg001 = require('./lib/eSignature/controllers/eg002SigningViaEmail');

const {
  eg002
} = require("./lib/eSignature/controllers");

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || 'localhost';
const max_session_min = 180;
const csrfProtection = csrf({ cookie: true });

let hostUrl = 'http://' + HOST + ':' + PORT
if (dsConfig.appUrl != '' && dsConfig.appUrl != '{APP_URL}') { hostUrl = dsConfig.appUrl }

let app = express()
  .use(helmet())
  .use(express.static(path.join(__dirname, 'public')))
  .use(cookieParser())
  .use(session({
    secret: dsConfig.sessionSecret,
    name: 'ds-launcher-session',
    cookie: { maxAge: max_session_min * 60000 },
    saveUninitialized: true,
    resave: true,
    store: new MemoryStore({
      checkPeriod: 86400000 // prune expired entries every 24h
    })
  }))
  .use(passport.initialize())
  .use(passport.session())
  .use(bodyParser.urlencoded({ extended: true }))
  .use(((req, res, next) => {
    res.locals.user = req.user;
    res.locals.session = req.session;
    res.locals.dsConfig = { ...dsConfig, docOptions: docOptions, docNames: docNames };
    res.locals.examplesApi = examplesApi
    res.locals.hostUrl = hostUrl; // Used by DSAuthCodeGrant#logout
    next()
  })) // Send user info to views
  .use(flash())
  .set('views', path.join(__dirname, 'views'))
  .set('view engine', 'ejs')
  // Add an instance of DSAuthCodeGrant to req
  .use((req, res, next) => {
    // req.dsAuthCodeGrant = new DSAuthCodeGrant(req);
    req.dsAuthJwt = new DsJwtAuth(req);
    // req.dsAuth = req.dsAuthCodeGrant;
    // if (req.session.authMethod === 'jwt-auth') {
      req.dsAuth = req.dsAuthJwt;
    // }
    next()
  })
  .use(async (req, res, next) => {
    let manifestUrl;

    switch(true) {
      case examplesApi.examplesApi.isRoomsApi:
        manifestUrl = dsConfig.roomsManifestUrl;
        break;

      case examplesApi.examplesApi.isClickApi:
        manifestUrl = dsConfig.clickManifestUrl;
        break;

      case examplesApi.examplesApi.isMonitorApi:
        manifestUrl = dsConfig.monitorManifestUrl;
        break;

      case examplesApi.examplesApi.isAdminApi:
        manifestUrl = dsConfig.adminManifestUrl;
        break;

      default:
        manifestUrl = dsConfig.eSignManifestUrl;
    }

    const manifest = await getManifest(manifestUrl);
    res.locals.manifest = manifest;

    next();
  })
  // Routes
  .get('/', commonControllers.indexController)
  // .get('/ds/choose_api', commonControllers.chooseApi)
  // .get('/ds/switch_api', commonControllers.switchApi)
  .get('/ds/login', commonControllers.login)
  .get('/ds/callback', [dsLoginCB1, dsLoginCB2]) // OAuth callbacks. See below
  .get('/ds/logout', commonControllers.logout)
  .get('/ds/logoutCallback', commonControllers.logoutCallback)
  .get('/ds/mustAuthenticate', commonControllers.mustAuthenticateController)
  .get('/ds-return', commonControllers.returnController)
  .use(csrfProtection) // CSRF protection for the following routes
;
if (examplesApi.examplesApi.isRoomsApi) {
  app.get('/eg001', eg001rooms.getController)
    .post('/eg001', eg001rooms.createController)
    .get('/eg002', eg002rooms.getController)
    .post('/eg002', eg002rooms.createController)
} else if (examplesApi.examplesApi.isClickApi) {
  app.get('/eg001', eg001click.getController)
    .post('/eg001', eg001click.createController)
    .get('/eg002', eg002click.getController)
    .post('/eg002', eg002click.createController)
} else if (examplesApi.examplesApi.isMonitorApi) {
  app.get('/eg001', eg001monitor.getController)
    .post('/eg001', eg001monitor.createController)
    .get('/eg002', eg002monitor.getController)
    .post('/eg002', eg002monitor.createController)
} else if (examplesApi.examplesApi.isAdminApi) {
    app.get('/eg001', eg001admin.getController)
    .post('/eg001', eg001admin.createController)
    .get('/eg002', eg002admin.getController)
    .post('/eg002', eg002admin.createController)
} else {
  app.get('/eg001', eg001.getController)
    .post('/eg001', eg001.createController)
    .get('/eg002', eg002.getController)
    .post('/eg002', eg002.createController)
}

function dsLoginCB1(req, res, next) { req.dsAuthCodeGrant.oauth_callback1(req, res, next) }
function dsLoginCB2(req, res, next) { req.dsAuthCodeGrant.oauth_callback2(req, res, next) }

/* Start the web server */
if (dsConfig.dsClientId && dsConfig.dsClientId !== '{CLIENT_ID}' &&
  dsConfig.dsClientSecret && dsConfig.dsClientSecret !== '{CLIENT_SECRET}') {
  app.listen(PORT)
  console.log(`Listening on ${PORT}`);
  console.log(`Ready! Open ${hostUrl}`);
} else {
  console.log(`PROBLEM: You need to set the clientId (Integrator Key), and perhaps other settings as well.
You can set them in the configuration file config/appsettings.json or set environment variables.\n`);
  process.exit(); // We're not using exit code of 1 to avoid extraneous npm messages.
}

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete DocuSign profile is serialized
//   and deserialized.
passport.serializeUser(function (user, done) { done(null, user) });
passport.deserializeUser(function (obj, done) { done(null, obj) });

const SCOPES = ["signature"];
const ROOM_SCOPES = [
  "signature", "dtr.rooms.read", "dtr.rooms.write",
  "dtr.documents.read", "dtr.documents.write", "dtr.profile.read", "dtr.profile.write",
  "dtr.company.read", "dtr.company.write", "room_forms"
];
const CLICK_SCOPES = [
  "signature", "click.manage", "click.send"
];
const MONITOR_SCOPES = [
  "signature", "impersonation"
];
const ADMIN_SCOPES = [
  "organization_read", "group_read", "permission_read	",
  "user_read", "user_write", "account_read",
  "domain_read", "identity_provider_read", "signature"
];
let scope;
if (examplesApi.examplesApi.isRoomsApi) {
  scope = ROOM_SCOPES;
} else if (examplesApi.examplesApi.isClickApi) {
  scope = CLICK_SCOPES;
} else if (examplesApi.examplesApi.isMonitorApi) {
  scope = MONITOR_SCOPES;
} else if (examplesApi.examplesApi.isAdminApi) {
  scope = ADMIN_SCOPES;
} else {
  scope = SCOPES;
}
// Configure passport for DocusignStrategy
let docusignStrategy = new DocusignStrategy({
    production: dsConfig.production,
    clientID: dsConfig.dsClientId,
    scope: scope.join(" "),
    clientSecret: dsConfig.dsClientSecret,
    callbackURL: hostUrl + '/ds/callback',
    state: true // automatic CSRF protection.
      // See https://github.com/jaredhanson/passport-oauth2/blob/master/lib/state/session.js
  },
  function _processDsResult(accessToken, refreshToken, params, profile, done) {
    // The params arg will be passed additional parameters of the grant.
    // See https://github.com/jaredhanson/passport-oauth2/pull/84
    //
    // Here we're just assigning the tokens to the account object
    // We store the data in DSAuthCodeGrant.getDefaultAccountInfo
    let user = profile;
    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    user.expiresIn = params.expires_in;
    user.tokenExpirationTimestamp = moment().add(user.expiresIn, 's'); // The dateTime when the access token will expire
    return done(null, user);
  }
);

/**
 * The DocuSign OAuth default is to allow silent authentication.
 * An additional OAuth query parameter is used to not allow silent authentication
 */
if (!dsConfig.allowSilentAuthentication) {
  // See https://stackoverflow.com/a/32877712/64904
  docusignStrategy.authorizationParams = function (options) {
    return { prompt: 'login' };
  }
}
passport.use(docusignStrategy);
