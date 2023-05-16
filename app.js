const debug = require('debug')('auth-example:server');
const path = require("path");
const http = require('http');
const express = require('express');
const session = require("express-session");
const logger = require('morgan');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const openidClient = require("openid-client");


// Config
require("dotenv").config();


const config = {
    "BASE_URL": process.env.BASE_URL || "http://localhost:8090",
    "STATIC_DIR": process.env.STATIC_DIR || path.join(__dirname, "static"),
    "SESSION_SECRET": process.env.SESSION_SECRET,
    "VV_ISSUER_URL": process.env.VV_ISSUER_URL,
    "VV_CLIENT_ID": process.env.VV_CLIENT_ID,
    "VV_CLIENT_SECRET": process.env.VV_CLIENT_SECRET,
};

const oidcCallbackUrl = new URL('/auth/callback', config.BASE_URL).toString();
const oidcLogoutUrl = new URL('/auth/logout', config.BASE_URL).toString();


let _oidcClient;
function getOidcClient() {
    return new Promise((resolve, reject) => {
        if (_oidcClient) {
            resolve(_oidcClient);
            return;
        }

        const cbResolve = (iss) => {
            _oidcClient = new iss.Client({
                client_id: config.VV_CLIENT_ID,
                client_secret: config.VV_CLIENT_SECRET,
                redirect_uris: [oidcCallbackUrl.toString()],
                response_types: ['code'],
            });
            resolve(_oidcClient);
        }
        const cbError = (err) => {
            reject(err);
        }
        openidClient.Issuer.discover(config.VV_ISSUER_URL)
            .then(cbResolve)
            .catch(cbError);
    });
}

function authMiddleware(prompt) {
    return function (req, res) {
        getOidcClient().then((oidcClient) => {
            const gens = openidClient.generators;
            const nonce = gens.nonce();
            const state = gens.state();
            const codeVerifier = gens.codeVerifier();
            const codeChallenger = gens.codeChallenge(codeVerifier);

            req.session.code_verifier = codeVerifier;
            req.session.nonce = nonce;
            req.session.state = state;

            const opts = {
                scope: 'openid email profile',
                code_challenge: codeChallenger,
                code_challenge_method: 'S256',
                nonce: nonce,
                state: state,
            }
            if (prompt) {
                opts["prompt"] = prompt;
            }

            const redir = oidcClient.authorizationUrl(opts);
            res.redirect(redir);
        }).catch((err) => {
            res.redirect('/');
        });
    };
}

const app = express();
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
    secret: config.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    httpOnly: true,
    name: "authsess",
    cookie: {
        secure: false,
        sameSite: 'lax',
    },
}));
app.use("/static", express.static(config.STATIC_DIR));

app.get('/', (req, res) => {
    const data = {
        user: req.session.userinfo,
        user_json: JSON.stringify(req.session.userinfo, null, " "),
        oidc: {
            issuer_url: config.VV_ISSUER_URL,
        },
    };
    getOidcClient().then((oidcClient) => {
        res.render('index', data);
    }).catch((err) => {
        data.oidc.error = err;
        res.render('index', data);
    });
});

// /login just redirects to /auth/login. But it could contain any app specific
// logic or a confirmation page that shows a login button.
app.get('/login', (req, res) => {
    res.redirect('/auth/login');
});

// /auth/login kicks off the OIDC flow by redirecting to Vault Vision. Once
// authentication is complete the user will be returned to /auth/callback.
app.get('/auth/login', authMiddleware());

// Once Vault Vision authenticates a user they will be sent here to complete
// the OIDC flow.
app.get('/auth/callback', (req, res) => {
    getOidcClient().then((oidcClient) => {
        const oidcParams = oidcClient.callbackParams(req);
        oidcClient.callback(oidcCallbackUrl, oidcParams, {
            code_verifier: req.session.code_verifier,
            state: req.session.state,
            nonce: req.session.nonce,
        }).then((tokenSet) => {

            // Vault Vision always provides an access token for the flows used
            // in this example.
            if (tokenSet.access_token) {
                oidcClient.userinfo(tokenSet.access_token).then((userinfo) => {
                    req.session.regenerate(function (err) {
                        if (err) {
                            next(err);
                        }

                        req.session.claims = tokenSet.claims();
                        req.session.userinfo = userinfo;
                        req.session.sessionTokens = tokenSet;
                        req.session.save(function (err) {
                            if (err) {
                                return next(err);
                            }
                            res.redirect('/');
                        });
                    });
                });
            } else {
                res.redirect("/");
            }
        });
    }).catch((err) => {
        console.log(err);
        res.redirect('/');
    });
});

// Logout clears the cookies and then sends the users to Vault Vision to clear
// the session, then Vault Vision will redirect the user to /auth/logout.
app.get('/logout', (req, res, next) => {
    req.session.userinfo = null;
    req.session.save(function (err) {
        if (err) {
            next(err);
        }
        req.session.regenerate(function (err) {
            if (err) {
                next(err);
            }

            const u = new URL('/logout', config.VV_ISSUER_URL);
            u.searchParams.set('client_id', config.VV_CLIENT_ID);
            u.searchParams.set('return_to', oidcLogoutUrl);
            res.redirect(u.toString());
        });
    });
});

// Once Vault Vision clears the users session, they return to this route.
app.get('/auth/logout', (req, res) => {
    res.redirect('/');
});

// /settings just redirects to /auth/settings. But it could contain any app 
// specific logic or a confirmation page that shows a settings button.
app.get('/settings', (req, res) => {
    res.redirect('/auth/settings');
});

// /auth/settings redirects to the Vault Vision settings page so users can
// manage their email, password, social logins, webauthn credentials and more.
//
// This works by using an oidc prompt named "settings". When the user returns
// your session will be updated to reflect any changes they made.
app.get('/auth/settings', authMiddleware("settings"));

// /introspect calls the introspection[1] endpoint. You may use this to see if
// the given token is still active.
//
// [1] https://datatracker.ietf.org/doc/html/rfc7662
app.get('/introspect', (req, res) => {
    getOidcClient().then((oidcClient) => {
        oidcClient.introspect(
            // For vault vision, we allow checking both the access_token and
            // the id_token.
            req.session.sessionTokens.access_token,
        ).then((introspectRes) => {
            res.status(200);
            res.json({
                response: introspectRes,
            });
        })
    }).catch((err) => {
        const data = {
            user: req.session.userinfo,
            user_json: JSON.stringify(req.session.userinfo, null, " "),
            oidc: {
                issuer_url: config.VV_ISSUER_URL,
            },
        };
        data.oidc.error = err;
        res.render('index', data);
    });
});

app.use(function (req, res, next) {
    next(createError(404));
});

app.use(function (err, req, res, next) {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    res.status(err.status || 500);
    res.json({
        message: err.message,
        error: err
    });
});

function runServer() {
    const server = http.createServer(app);
    server.on('error', function (error) {
        if (error.syscall !== 'listen') {
            throw error;
        }

        var bind = typeof port === 'string'
            ? 'Pipe ' + port
            : 'Port ' + port;

        // handle specific listen errors with friendly messages
        switch (error.code) {
            case 'EACCES':
                console.error(bind + ' requires elevated privileges');
                process.exit(1);
                break;
            case 'EADDRINUSE':
                console.error(bind + ' is already in use');
                process.exit(1);
                break;
            default:
                throw error;
        }
    });
    server.on('listening', function () {
        var addr = server.address();
        var bind = typeof addr === 'string'
            ? 'pipe ' + addr
            : 'port ' + addr.port;
        debug('Listening on ' + bind);
    });

    const baseUrl = new URL(config.BASE_URL);
    server.listen(parseInt(baseUrl.port, 10), baseUrl.hostname);
}

runServer();
