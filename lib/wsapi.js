// an abstraction that implements all of the cookie handling, CSRF protection,
// etc of the wsapi.  This module also routes request to the approriate handlers
// underneath wsapi/
//
// each handler under wsapi/ supports the following exports:
//   exports.process - function(req, res) - process a request 
//   exports.writes_db - must be true if the processing causes a database write
//   exports.method - either 'get' or 'post' 

const
wsapi = require('./browserid/wsapi.js'),
sessions = require('connect-cookie-session'),
express = require('express');
secrets = require('./secrets'),
config = require('./configuration'),
logger = require('./logging.js').logger,
httputils = require('./httputils.js');

const COOKIE_SECRET = secrets.hydrateSecret('browserid_cookie', config.get('var_path'));
const COOKIE_KEY = 'browserid_state';

exports.setup = function(app) {

  // If externally we're serving content over SSL we can enable things
  // like strict transport security and change the way cookies are set
  const overSSL = (config.get('scheme') == 'https');

  app.use(express.cookieParser());

  var cookieSessionMiddleware = sessions({
    secret: COOKIE_SECRET,
    key: COOKIE_KEY,
    cookie: {
      path: '/wsapi',
      httpOnly: true,
      // IMPORTANT: we allow users to go 1 weeks on the same device
      // without entering their password again
      maxAge: config.get('authentication_duration_ms'),
      secure: overSSL
    }
  });

  // cookie sessions && cache control
  app.use(function(req, resp, next) {
    // cookie sessions are only applied to calls to /wsapi
    // as all other resources can be aggressively cached
    // by layers higher up based on cache control headers.
    // the fallout is that all code that interacts with sessions
    // should be under /wsapi
    if (/^\/wsapi/.test(req.url)) {
      // explicitly disallow caching on all /wsapi calls (issue #294)
      resp.setHeader('Cache-Control', 'no-cache, max-age=0');

      // we set this parameter so the connect-cookie-session
      // sends the cookie even though the local connection is HTTP
      // (the load balancer does SSL)
      if (overSSL)
        req.connection.proxySecure = true;

      return cookieSessionMiddleware(req, resp, next);

    } else {
      return next();
    }
  });

  // verify all JSON responses are objects - prevents regression on issue #217
  app.use(function(req, resp, next) {
    var realRespJSON = resp.json;
    resp.json = function(obj) {
      if (!obj || typeof obj !== 'object') {
        logger.error("INTERNAL ERROR!  *all* json responses must be objects");
        throw "internal error";
      }
      realRespJSON.call(resp, obj);
    };
    return next();
  });

  app.use(express.bodyParser());

  // Check CSRF token early.  POST requests are only allowed to
  // /wsapi and they always must have a valid csrf token
  app.use(function(req, resp, next) {
    // only on POSTs
    if (req.method == "POST") {
      var denied = false;
      if (!/^\/wsapi/.test(req.url)) { // post requests only allowed to /wsapi
        denied = true;
        logger.warn("CSRF validation failure: POST only allowed to /wsapi urls.  not '" + req.url + "'");
      }

      else if (req.session === undefined) { // there must be a session
        denied = true;
        logger.warn("CSRF validation failure: POST calls to /wsapi require an active session");
      }

      // the session must have a csrf token
      else if (typeof req.session.csrf !== 'string') {
        denied = true;
        logger.warn("CSRF validation failure: POST calls to /wsapi require an csrf token to be set");
      }

      // and the token must match what is sent in the post body
      else if (req.body.csrf != req.session.csrf) {
        denied = true;
        // if any of these things are false, then we'll block the request
        logger.warn("CSRF validation failure, token mismatch. got:" + req.body.csrf + " want:" + req.session.csrf);
      }

      if (denied) return httputils.badRequest(resp, "CSRF violation");

    }
    return next();
  });

  wsapi.setup(app);
};
