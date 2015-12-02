var acToken = require('../../shared/acToken'),
    acQueries = require('../../shared/acQueries'),
    acMisc = require('../../shared/acMisc'),
    CONSTANTS = require('../../shared/CONSTANTS'),
    acFirebaseNode = require('../../shared/acFirebaseNode'),
    Q = require('q'),
    async = require('async'),
    UserHelper = require('./userHelper'),
    https = require('https'),
    request = require('request'),
    acLogger = require('../../shared/acLogger');

var logger = new acLogger('authHelper');
var userHelper = new UserHelper();

var AuthHelper = module.exports = function AuthHelper() {

    this.noAccount = {
        status: 'NO_ACCOUNT',
        code: 0,
        type: 'NO_USER',
        message: 'Email or Password is incorrect'
    };

    this.shouldCreateAccount = {
        status: 'CREATE_ACCOUNT',
        code: 0,
        type: 'NO_USER',
        message: 'User account does not exist, create one'
    };

    this.emailInUse = {
        status: 'EMAIL_IN_USE',
        code: 0,
        type: 'NO_USER',
        message: 'The email address for this Google account is in use by another account'
    };

    this.liveEmailInUse = {
        status: 'EMAIL_IN_USE',
        code: 0,
        type: 'NO_USER',
        message: 'The email address for this Live account is in use by another account'
    };

    this.badJWT = {
        status: 'FAIL',
        code: 0,
        type: 'BAD_TOKEN',
        message: 'Error decoding JWT token'
    };

    this.fail = function(code, message) {
        var error = {};
        error.status = 'FAIL';
        error.code = code;
        error.message = message;

        return error;
    };
};

AuthHelper.prototype.loginWithGoogle = function(body, cb) {

    var self = this;
   
    async.waterfall(
        [
            // convert code to tokens, check if google id or google email are already in an account
            //
            function(callback) {
                if(body.marketing_site){
                    self.generateResponseForMarketingSite(body, function(error,context){
                        callback(null, context);
                    });
                }else{
                    self.doesGoogleAccountExist(body, function(error, context) {
                    
                        if(!error) {
                            callback(null, context);
                        } else {
                            if(error.status === 'CREATE_ACCOUNT') {
                                self.createGoogleUser(context, function(err, context) {

                                    if(err) {
                                        self.deleteUser(context, function() {
                                            cb(err, null);
                                        });
                                    } else {
                                        self.generateResponse(context, function(error, context) {
                                            callback('ACCOUNT_CREATED', context);
                                        });
                                    }
                                });
                            } else {
                                callback(error, null);
                            }
                        }
                    });
                }
            },

            function(context, callback) {
                self.serverSideLogin(context, function(error, context) {
                    callback(error, context);
                });
            }
        ],
        function(error, context) {

            if(error && error !== 'ACCOUNT_CREATED') {
                cb(error, null);
            } else {
                cb(null, context);
            }
        }
    );
};

AuthHelper.prototype.createUserWithGoogle = function(body, cb) {

    var self = this;

    async.waterfall(
        [
            // convert code to tokens, check if google id or google email are already in an account
            //
            function(callback) {
                self.doesGoogleAccountExist(body, function(error, context) {
                    if(!error) {
                        // Login if account already exists
                        self.serverSideLogin(context, function(error, context) {
                            callback('LOGIN', context);
                        });
                    } else {
                        if(error.status === 'CREATE_ACCOUNT') {
                            context.user = body.user;
                            callback(null, context);
                        } else {
                            callback(error, null);
                        }
                    }
                });
            },

            // create the user
            function(context, callback) {
                self.createGoogleUser(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get user state
            function(context, callback) {
                userHelper.getUserActivationState(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            },

            // generate response
            function(context, callback) {
                self.generateResponse(context, function(error, context) {
                    callback(error, context);
                });
            }
        ],
        function(error, context) {

            if(error && error !== 'LOGIN') {
                if(error.status !== 'EMAIL_IN_USE') {
                    self.deleteUser(context, function() {
                        cb(error, null);
                    });
                } else {
                    cb(error, null);
                }
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.loginWithBasicAuth = function(body, cb) {

    var self = this;

    async.waterfall(
        [
            function(callback) {
                userHelper.validateBasicAuth(body.email, body.password).then(function(uid) {

                        if(!uid) {
                            callback(self.noAccount, null);
                        } else {
                            var context = {
                                uid: uid
                            };
                            callback(null, context);
                        }
                    },
                    function(message) {
                        callback(message || self.noAccount, null);
                    });
            },

            // get user state
            function(context, callback) {
                userHelper.getUserActivationState(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            },

            // generate response
            function(context, callback) {
                self.generateResponse(context, function(error, context) {
                        callback(error, context);
                    },
                    function(error) {
                        callback(error, null);
                    });
            }
        ],
        function(error, context) {

            if(error) {
                cb(error, null);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.createUserWithBasicAuth = function(user, cb) {

    var self = this;

    async.waterfall(
        [
            // check to see if user exists
            function(callback) {
                var context = {
                    user: user,
                    email: user.email.toLowerCase(),
                    password: user.password
                };

                acQueries.getUidByEmail(context.email).then(function(uid) {
                    if(uid) {
                        callback(self.emailInUse, null);
                    } else {
                        callback(null, context);
                    }
                });
            },

            // create the user
            function(context, callback) {

                userHelper.createBasicAuthHash(context.password, function(error, hash) {
                        if(error) {
                            callback(error, null);
                        } else {
                            context.hash = hash;
                            callback(null, context);
                        }
                    },
                    function(error) {
                        callback(error, null);
                    });
            },

            // create air class user
            function(context, callback) {
                userHelper.createAirClassUser(context, function(err, context) {
                    callback(err, context);
                });
            },

            // get user state
            function(context, callback) {
                userHelper.getUserActivationState(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            },

            // generate response
            function(context, callback) {
                self.generateResponse(context, function(error, context) {
                        callback(error, context);
                    },
                    function(error) {
                        callback(error, null);
                    });
            }
        ],
        function(error, context) {

            if(error) {
                if(error.status !== 'EMAIL_IN_USE') {
                    self.deleteUser(context, function() {
                        cb(error, null);
                    });
                } else {
                    cb(error, null);
                }
            } else {
                cb(null, context);
            }
        }
    );
};

AuthHelper.prototype.deleteUser = function(context, cb) {
    var self = this;

    async.waterfall(
        [
            // delete the public profile
            function(callback) {
                userHelper.deletePublicProfile(context, function(err, context) {
                    callback(err, context);
                });
            },

            // delete the private profile
            function(context, callback) {
                userHelper.deletePrivateProfile(context, function(err, context) {
                    callback(err, context);
                });
            },

            // revoke google auth
            function(context, callback) {
                if(context.googleTokens) {
                    self.revokeGoogleToken(context.googleTokens).then(function() {
                            callback(null, context);
                        },
                        function(err) {
                            logger.error(err);
                            callback(null, context);
                        });
                } else {
                    callback(null, context);
                }
            }
        ],
        function(error, context) {
            cb(error, context);
        }
    );
};

AuthHelper.prototype.linkGoogleAccount = function(body, cb) {

    var self = this;

    async.waterfall(
        [
            function(callback) {
                var context = {};

                context.uid = body.uid;

                context.accessTokenUrl = 'https://accounts.google.com/o/oauth2/token';
                context.params = {
                    code: body.code,
                    client_id: body.clientId,
                    client_secret: CONSTANTS.GOOGLE_CLIENT_SECRET,
                    redirect_uri: body.redirectUri,
                    grant_type: 'authorization_code'
                };

                callback(null, context);
            },
            function(context, callback) {

                self.exchangeGoogleCodeForTokens(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                acQueries.getUidByGoogleId(context.googleId).then(function(uId) {
                    if(uId && uId !== context.uid) {
                        callback({
                            status: 'GOOGLE_ID_IN_USE',
                            code: 0,
                            type: 'NO_LINK',
                            message: 'Google Id already in use'
                        }, null);
                    } else {
                        callback(null, context);
                    }
                });
            },
            function(context, callback) {
                userHelper.setGoogleUserMeta(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                context.response = {};
                context.response.link = context.googleEmail;
                context.response.status = 'SUCCESS';
                callback(null, context);
            }
        ],
        function(error, context) {
            cb(error, context);
        }
    );
};

AuthHelper.prototype.exchangeGoogleCodeForTokens = function(context, callback) {
    request.post(context.accessTokenUrl, {
        json: true,
        form: context.params
    }, function(err, response, tokens) {
        if(err) {
            callback(err, null);
        } else if(tokens && tokens.id_token) {
            var encodedId = tokens.id_token.split('.')[1];
            var id = JSON.parse((new Buffer(encodedId, 'base64')).toString());
            logger.log(id);

            context.email = id.email;

            context.googleId = id.sub;
            context.googleEmail = id.email;
            context.googleTokens = tokens;

            callback(null, context);
        } else {
            // fail - we don't know who they are
            logger.error('no id_token');
            callback(Error('no id_token'), null);
        }
    });
};

AuthHelper.prototype.doesGoogleAccountExist = function(body, cb) {
    var self = this;
  
    async.waterfall(
        [
            function(callback) {
                var context = {};

                context.accessTokenUrl = 'https://accounts.google.com/o/oauth2/token';

                context.params = {
                    code: body.code,
                    client_id: body.clientId,
                    client_secret: CONSTANTS.GOOGLE_CLIENT_SECRET,
                    redirect_uri: body.redirectUri,
                    grant_type: 'authorization_code'
                };

                callback(null, context);
            },

            // Exchange authorization code for access token.
            // get google id & email from id_token

            function(context, callback) {
                self.exchangeGoogleCodeForTokens(context, function(error, context) {
                    callback(error, context);
                });
            },

            // use googleId to get UID
            //  if it fails then check the email for an UID
            //
            function(context, callback) {
                acQueries.getUidByGoogleId(context.googleId).then(function(uid) {
                        if(!uid) {

                            acQueries.getUidByEmail(context.googleEmail).then(function(uid) {
                                //if there is a uid then revoke the google token and return EMAIL_IN_USE error
                                if(uid) {
                                    self.revokeGoogleToken(context.googleTokens).then(function() {
                                            callback(self.emailInUse, null);
                                        },
                                        function() {
                                            callback(self.emailInUse, null);
                                        });
                                } else {
                                    callback(self.shouldCreateAccount, context);
                                }
                            });

                        } else {
                            context.uid = uid;
                            callback(null, context);
                        }
                    },
                    function() {
                        callback(self.noAccount, null);
                    });
            }
        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.createGoogleUser = function(context, cb) {

    async.waterfall(
        [
            // get the users google profile
            function(callback) {
                userHelper.getGoogleProfile(context, function(err, context) {
                    callback(err, context);
                });
            },

            // create air class user
            function(context, callback) {
                context.isGoogleAccount = true;
                userHelper.createAirClassUser(context, function(err, context) {
                    callback(err, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            }

        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.serverSideLogin = function(context, cb) {
    var self = this;

    async.waterfall(
        [
            // save tokens
            function(callback) {
                if((context.googleTokens && context.googleTokens.access_token) || (context.liveTokens && context.liveTokens.access_token)) {
                    var type = (context.googleTokens && context.googleTokens.access_token) ? 'google' : 'live';
                    var accessToken = type === 'google' ? context.googleTokens.access_token : context.liveTokens.access_token;
                    var refreshToken = type === 'google' ? context.googleTokens.refresh_token : context.liveTokens.refresh_token;
                    userHelper.saveSingleTokenInFirebase(type, context.uid, 'access_token', accessToken).then(function() {
                            // we think this should not happen often but if we do get a new refresh token save it
                            if(refreshToken) {
                                userHelper.saveSingleTokenInFirebase(type, context.uid, 'refresh_token', refreshToken).then(function() {
                                        callback(null, context);
                                    },
                                    function(error) {
                                        callback(error, null);
                                    });
                            } else {
                                callback(null, context);
                            }
                        },
                        function(error) {
                            callback(error, null);
                        });
                } else {
                    callback(null, context);
                }
            },

            // get user state
            function(context, callback) {
                userHelper.getUserActivationState(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            },

            // generate response
            function(context, callback) {
                self.generateResponse(context, function(error, context) {
                    callback(error, context);
                });
            }
        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.generateResponse = function(context, callback) {

    var token = acToken.generateToken({
        'uid': context.uid
    });
    var r = {
        status: 'SUCCESS',
        token: token
    };

    r.user = context.user;
    r.roles = context.roles;
    r.activated = context.activated;

    acMisc.generateAcRefreshToken(context.uid).then(function(acRefreshToken) {
            r.acRefreshToken = acRefreshToken;
            context.response = r;
            callback(null, context);
        },
        function() {
            callback({
                type: 'ERROR_AC_REFRESH_TOKEN',
                message: 'Error generating an AirClass refresh token'
            }, null);
        });
};

AuthHelper.prototype.revokeGoogleToken = function(googleTokens) {
    var deferred = Q.defer();

    if(!googleTokens) {
        deferred.reject('no tokens');
    } else {
        //https://accounts.google.com/o/oauth2/revoke?token={token}
        https.get('https://accounts.google.com/o/oauth2/revoke?token=' + googleTokens.access_token, function() {
            deferred.resolve();
        }).on('error', function() {
            deferred.reject({
                type: 'GOOGLE_REVOKE_ERROR',
                message: 'Error revoking google oauth tokens'
            });
        });
    }

    return deferred.promise;
};

AuthHelper.prototype.refreshGoogleToken = function(refreshToken) {
    var deferred = Q.defer();

    var params = {
        client_id: CONSTANTS.GOOGLE_CLIENT_ID,
        client_secret: CONSTANTS.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
    };

    request.post('https://www.googleapis.com/oauth2/v3/token', {
        json: true,
        form: params
    }, function(err, response, tokens) {
        if(err) {
            deferred.reject(err);
        } else
        if(tokens.error) {
            deferred.reject(tokens);
        } else {
            deferred.resolve(tokens);
        }
    });

    return deferred.promise;
};

// only resolve, even on error
AuthHelper.prototype.validateGoogleToken = function(accessToken) {
    var deferred = Q.defer();

    request.get('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + accessToken)
        .on('data', function(data) {

            var reply = JSON.parse(data);
            if(reply.error || (!reply.error && reply.audience !== CONSTANTS.GOOGLE_CLIENT_ID)) { // avoid confused deputy problem
                deferred.resolve({
                    error: (reply.error || 'Invalid_token'),
                    error_description: (reply.error_description || 'The access_token is not from Air Class!')
                });
            }
            deferred.resolve(reply);
        })
        .on('error', function() {
            deferred.resolve({
                error: 'Invalid_token',
                error_description: 'The access_token cannot be validated'
            });
        });

    return deferred.promise;
};

AuthHelper.prototype.getGoogleAccessToken = function(uid) {
    var deferred = Q.defer();
    var self = this;
    var googleTokens;
    var retVal = {};

    // get the google access token
    userHelper.getGoogleTokens(uid).then(function(tokens) {
        googleTokens = tokens;

        // validate it
        if(googleTokens && googleTokens.access_token) {
            self.validateGoogleToken(googleTokens.access_token).then(function(result) {
                if(result.error) {
                    // token isn't valid
                    self.refreshGoogleToken(googleTokens.refresh_token).then(function(result) {
                        var newTokens = result;
                        if(newTokens.access_token) {
                            retVal.access_token = newTokens.access_token;
                            retVal.expires_in = newTokens.expires_in;
                            userHelper.saveSingleTokenInFirebase('google', uid, 'access_token', newTokens.access_token).then(function() {
                                    deferred.resolve(retVal);
                                },
                                function(error) {
                                    deferred.reject(error);
                                });
                        }
                    }, function(error) {
                        deferred.reject({
                            status: 'FAIL',
                            code: 404,
                            message: error.toString()
                        });
                    });
                } else {
                    // token is valid
                    retVal.access_token = googleTokens.access_token;
                    retVal.expires_in = result.expires_in;
                    deferred.resolve(retVal);
                }
            });
        } else {
            deferred.reject({
                status: 'FAIL',
                code: 404,
                message: 'Their is no google token'
            });
        }
    });

    return deferred.promise;
};

AuthHelper.prototype.unlinkGoogleAccount = function(uid) {
    var self = this;

    var deferred = Q.defer();

    async.waterfall(
        [
            function(callback) {

                userHelper.getGoogleTokens(uid).then(function(tokens) {
                        callback(null, tokens);
                    },
                    function(err) {
                        callback(err, null);
                    });
            },
            function(tokens, callback) {

                self.revokeGoogleToken(tokens).then(function() {
                        callback(null, 'revoked');
                    },
                    function(err) {
                        callback(err, null);
                    });
            },
            function(status, callback) {
                userHelper.clearGoogleUserMeta(uid, function(error) {
                    callback(error, 'done');
                });
            }
        ],
        function(error, state) {
            if(error) {
                deferred.reject(error);
            } else {
                deferred.resolve(state);
            }
        }
    );

    return deferred.promise;
};

/*
 * Microsoft Live helpers
 */
AuthHelper.prototype.loginWithLive = function(body, cb) {
    var self = this;

    async.waterfall(
        [
            // convert code to tokens, check if live id or live email are already in an account
            function(callback) {
                self.doesLiveAccountExist(body, function(error, context) {
                    if(!error) {
                        callback(null, context);
                    } else {
                        if(error.status === 'CREATE_ACCOUNT') {
                            self.createLiveUser(context, function(err, context) {

                                if(err) {
                                    self.deleteUser(context, function() {
                                        cb(err, null);
                                    });
                                } else {
                                    self.generateResponse(context, function(error, context) {
                                        callback('ACCOUNT_CREATED', context);
                                    });
                                }
                            });
                        } else {
                            callback(error, null);
                        }
                    }
                });
            },

            function(context, callback) {

                self.serverSideLogin(context, function(error, context) {
                    callback(error, context);
                });
            }
        ],
        function(error, context) {

            if(error && error !== 'ACCOUNT_CREATED') {
                cb(error, null);
            } else {
                cb(null, context);
            }
        }
    );
};

AuthHelper.prototype.createUserWithLive = function(body, cb) {
    var self = this;

    async.waterfall(
        [
            // convert code to tokens, check if live id or live email are already in an account
            function(callback) {
                self.doesLiveAccountExist(body, function(error, context) {
                    if(!error) {
                        // Login if account already exists
                        self.serverSideLogin(context, function(error, context) {
                            callback('LOGIN', context);
                        });
                    } else {
                        if(error.status === 'CREATE_ACCOUNT') {
                            context.user = body.user;
                            callback(null, context);
                        } else {
                            callback(error, null);
                        }
                    }
                });
            },

            // create the user
            function(context, callback) {
                self.createLiveUser(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get user state
            function(context, callback) {
                userHelper.getUserActivationState(context, function(error, context) {
                    callback(error, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            },

            // generate response
            function(context, callback) {
                self.generateResponse(context, function(error, context) {
                    callback(error, context);
                });
            }
        ],
        function(error, context) {

            if(error && error !== 'LOGIN') {
                if(error.status !== 'EMAIL_IN_USE') {
                    self.deleteUser(context, function() {
                        cb(error, null);
                    });
                } else {
                    cb(error, null);
                }
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.linkLiveAccount = function(body, cb) {

    var self = this;

    async.waterfall(
        [
            function(callback) {
                var context = {};
                context.uid = body.uid;
                context.accessTokenUrl = 'https://login.live.com/oauth20_token.srf';
                context.params = {
                    code: body.code,
                    client_id: body.clientId,
                    client_secret: CONSTANTS.LIVE_CLIENT_SECRET,
                    redirect_uri: body.redirectUri,
                    grant_type: 'authorization_code'
                };

                self.exchangeLiveCodeForTokens(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                acQueries.getUidByLiveId(context.liveId).then(function(uId) {
                    if(uId && uId !== context.uid) {
                        callback({
                            status: 'LIVE_ID_IN_USE',
                            code: 0,
                            type: 'NO_LINK',
                            message: 'Live Id already in use'
                        }, null);
                    } else {
                        callback(null, context);
                    }
                });
            },
            function(context, callback) {
                self.getLiveUserInfo(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                userHelper.setLiveUserMeta(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                context.response = {};
                context.response.link = context.liveEmail;
                context.response.status = 'SUCCESS';
                callback(null, context);
            }
        ],
        function(error, context) {
            cb(error, context);
        }
    );
};

AuthHelper.prototype.exchangeLiveCodeForTokens = function(context, callback) {
    request.post(context.accessTokenUrl, {
        json: true,
        form: context.params
    }, function(err, response, tokens) {
        if(err) {
            callback(err, null);
        } else if(tokens && tokens.user_id) {
            context.liveId = tokens.user_id;
            context.liveTokens = tokens;

            callback(null, context);
        } else {
            // fail - we don't know who they are
            logger.error('no user_id');
            callback(Error('no user_id'), null);
        }
    });
};

AuthHelper.prototype.getLiveUserInfo = function(context, callback) {
    request.get('https://apis.live.net/v5.0/me/?access_token=' + context.liveTokens.access_token,
        function(error, response, body) {
            if(error) {
                callback(error, null);
            } else {
                var reply = JSON.parse(body);
                context.liveEmail = reply.emails.account;
                context.profile = {};
                context.profile.given_name = reply.first_name;
                context.profile.family_name = reply.last_name;
                context.profile.picture = 'https://apis.live.net/v5.0/' + reply.id + '/picture';
                callback(null, context);
            }
        });
};

AuthHelper.prototype.getOneDriveFileDetails = function(token, classId, fileId, oneDriveFileId) {
    var deferred = Q.defer();

    request.get('https://api.onedrive.com/v1.0/drive/items/' + oneDriveFileId + '/?access_token=' + token.access_token,
        function(error, response, body) {
            if(body.error) {
                deferred.reject(error);
            } else {
                var meta = JSON.parse(body);
                var details = {
                    downloadLink: meta['@content.downloadUrl'],
                    fileName: meta.name,
                    fileSizeKb: meta.size / 1024,
                    createdDate: (new Date(meta.createdDateTime)).getTime(),
                    lastModifiedBy: meta.lastModifiedBy.user.displayName,
                    lastModifiedDate: (new Date(meta.lastModifiedDateTime)).getTime(),
                    lastCheckedByAirClass: Date.now()
                };

                var url = 'https://api.onedrive.com/v1.0/drive/items/' + oneDriveFileId + '/thumbnails';
                url += '/?access_token=' + token.access_token;
                url += '&select=c330x330_Crop,c160x160_Crop';
                request.get(url,
                    function(error, response, body) {
                        if(error) {
                            deferred.reject(error);
                        } else {
                            var thumbnails = JSON.parse(body);
                            if(thumbnails.value.length > 0) {
                                details.thumbnail = thumbnails.value[0].c160x160_Crop.url;
                                details.thumbnailMedium = thumbnails.value[0].c330x330_Crop.url;
                            } else {
                                details.thumbnail = '';
                                details.thumbnailMedium = '';
                            }

                            acFirebaseNode('classLibrary/' + classId + '/fileLocker/' + fileId + '/details').update(details, function(error) {
                                if(error) {
                                    deferred.reject(error);
                                } else {
                                    deferred.resolve(details);
                                }
                            });
                        }
                    });
            }
        });
    return deferred.promise;
};

AuthHelper.prototype.doesLiveAccountExist = function(body, cb) {
    var self = this;

    async.waterfall(
        [
            function(callback) {
                var context = {};

                context.accessTokenUrl = 'https://login.live.com/oauth20_token.srf';

                context.params = {
                    code: body.code,
                    client_id: body.clientId,
                    client_secret: CONSTANTS.LIVE_CLIENT_SECRET,
                    redirect_uri: body.redirectUri,
                    grant_type: 'authorization_code'
                };

                callback(null, context);
            },

            // Exchange authorization code for access token.
            // get google id & email from id_token

            function(context, callback) {

                self.exchangeLiveCodeForTokens(context, function(error, context) {
                    callback(error, context);
                });
            },

            function(context, callback) {
                self.getLiveUserInfo(context, function(error, context) {
                    callback(error, context);
                });
            },

            // use liveId to get UID
            //  if it fails then check the email for an UID
            //
            function(context, callback) {
                acQueries.getUidByLiveId(context.liveId).then(function(uid) {
                        if(!uid) {

                            acQueries.getUidByEmail(context.liveEmail).then(function(uid) {
                                if(uid) {
                                    callback(self.emailInUse, null);
                                } else {
                                    callback(self.shouldCreateAccount, context);
                                }
                            });

                        } else {
                            context.uid = uid;
                            callback(null, context);
                        }
                    },
                    function() {
                        callback(self.noAccount, null);
                    });
            }
        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.createLiveUser = function(context, cb) {

    async.waterfall(
        [
            // create air class user
            function(callback) {
                context.isLiveAccount = true;
                userHelper.createAirClassUser(context, function(err, context) {
                    callback(err, context);
                });
            },

            // get the user public profile
            function(context, callback) {
                userHelper.getUserPublicProfile(context, function(error, context) {
                    callback(error, context);
                });
            }

        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );
};

AuthHelper.prototype.refreshLiveToken = function(refreshToken) {
    var deferred = Q.defer();

    var params = {
        client_id: CONSTANTS.LIVE_CLIENT_ID,
        client_secret: CONSTANTS.LIVE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
    };

    request.post('https://login.live.com/oauth20_token.srf', {
        json: true,
        form: params
    }, function(err, response, tokens) {
        if(err) {
            deferred.reject(err);
        } else
        if(tokens.error) {
            deferred.reject(tokens);
        } else {
            deferred.resolve(tokens);
        }
    });

    return deferred.promise;
};

// only resolve, even on error
AuthHelper.prototype.validateLiveToken = function(accessToken) {
    var deferred = Q.defer();

    request.get('https://apis.live.net/v5.0/me/permissions?access_token=' + accessToken)
        .on('data', function(data) {

            var reply = JSON.parse(data);
            if(reply.error || (!reply.error && reply.audience !== CONSTANTS.LIVE_CLIENT_ID)) { // avoid confused deputy problem
                deferred.resolve({
                    error: (reply.error || 'Invalid_token'),
                    error_description: (reply.error_description || 'The access_token is not from Air Class!')
                });
            }
            deferred.resolve(reply);
        })
        .on('error', function() {
            deferred.resolve({
                error: 'Invalid_token',
                error_description: 'The access_token cannot be validated'
            });
        });

    return deferred.promise;
};

AuthHelper.prototype.getLiveAccessToken = function(uid) {
    var deferred = Q.defer();
    var self = this;
    var liveTokens;
    var retVal = {};

    userHelper.getLiveTokens(uid).then(function(tokens) {
        liveTokens = tokens;

        if(liveTokens && liveTokens.access_token) {
            self.validateLiveToken(liveTokens.access_token).then(function(result) {
                if(result.error) {
                    // token isn't valid
                    self.refreshLiveToken(liveTokens.refresh_token).then(function(result) {
                        var newTokens = result;
                        if(newTokens.access_token) {
                            retVal.access_token = newTokens.access_token;
                            retVal.expires_in = newTokens.expires_in;
                            userHelper.saveSingleTokenInFirebase('live', uid, 'access_token', newTokens.access_token).then(function() {
                                    deferred.resolve(retVal);
                                },
                                function(error) {
                                    deferred.reject(error);
                                });
                        }
                    });
                } else {
                    // token is valid
                    retVal.access_token = liveTokens.access_token;
                    retVal.expires_in = result.expires_in;
                    deferred.resolve(retVal);
                }
            });
        } else {
            deferred.reject({
                status: 'FAIL',
                code: 404,
                message: 'There is no live token'
            });
        }
    });

    return deferred.promise;
};

AuthHelper.prototype.unlinkLiveAccount = function(uid) {
    var deferred = Q.defer();

    //cannot revoke tokens, so all we can do is remove meta data
    userHelper.clearLiveUserMeta(uid, function(error) {
        if(error) {
            deferred.reject(error);
        } else {
            deferred.resolve('done');
        }
    });

    return deferred.promise;
};

AuthHelper.prototype.generateResponseForMarketingSite = function(body,cb){

     async.waterfall(
        [
            // get the users google profile
            function(callback) {
                 var context = {
                    //server:"https://localhost:8080",
                    //accessTokenUrl:"https://accounts.google.com/o/oauth2/token",
                    params:{
                        client_id:body.client_id,
                        client_secret:CONSTANTS.GOOGLE_CLIENT_MARKETING_SECRET,
                    //    redirect_uri:"https://localhost:8080",
                    //    grant_type:"authorization_code"
                    }
                };
                //TODO see if you can change some of these hardcoded params around and have it still work
                
                var encodedId = body.id_token.split('.')[1];
                var id = JSON.parse((new Buffer(encodedId, 'base64')).toString());
                logger.log(id);   
                context.email = id.email;
                context.googleId = id.sub;
                context.googleEmail = id.email;
                context.googleTokens = {
                    access_token:body.access_token,
                    token_type:"Bearer",
                    expires_in:body.expires,
                    id_token:body.id_token
                };


                callback(null, context);
            },
            function(context, callback) {
                acQueries.getUidByGoogleId(context.googleId).then(function(uId) {
                   context.uid = uId;
                   callback(null, context);
                });
            },
            function(context, callback) {
                console.log("setting Meta right?");
                userHelper.setGoogleUserMeta(context, function(error, context) {
                    callback(error, context);
                });
            },
            function(context, callback) {
                context.response = {};
                context.response.link = context.googleEmail;
                context.response.status = 'SUCCESS';
                callback(null, context);
            }

        ],
        function(error, context) {

            if(error) {
                cb(error, context);
            } else {
                cb(null, context);

            }
        }
    );

};