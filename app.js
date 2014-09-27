require('newrelic');
require('memcache');

var client = new memcache.Client(11211, 'localhost');
client.connect();

var _ = require('underscore');
var async = require('async');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var ect = require('ect');
var express = require('express');
var logger = require('morgan');
var mysql = require('mysql');
var path = require('path');
var session = require('express-session');
var strftime = require('strftime');

var app = express();

var globalConfig = {
    userLockThreshold: process.env.ISU4_USER_LOCK_THRESHOLD || 3,
    ipBanThreshold: process.env.ISU4_IP_BAN_THRESHOLD || 10
};

var mysqlPool = mysql.createPool({
    host: process.env.ISU4_DB_HOST || 'localhost',
    user: process.env.ISU4_DB_USER || 'root',
    password: process.env.ISU4_DB_PASSWORD || '',
    database: process.env.ISU4_DB_NAME || 'isu4_qualifier'
});


var helpers = {
    calculatePasswordHash: function(password, salt) {
        var c = crypto.createHash('sha256');
        c.update(password + ':' + salt);
        return c.digest('hex');
    },

    isUserLocked: function(login, callback) {
        if(!login) {
            return callback(false);
        };

        client.gets('locked_users',function(err,locked_users){
            var index = locked_users.indexOf(login);
            if(index !== -1){
                callback(true);
            }else{
                callback(false);
            }
        })

    },

    isIPBanned: function(ip, callback) {
        client.gets('locked_ips',function(err,locked_ips){
            var index = locked_ips.indexOf(ip);
            if(index !== -1){
                callback(true);
            }else{
                callback(false);
            }
        })
        
    },

    attemptLogin: function(req, callback) {
        var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        var login = req.body.login;
        var password = req.body.password;

        async.waterfall([
            function(cb) {
                cb(null,login);
            },
            function(login, cb) {
                helpers.isIPBanned(ip, function(banned) {
                    if(banned) {
                        cb('banned', login);
                    } else {
                        cb(null, login);
                    };
                });
            },
            function(login, cb) {
                helpers.isUserLocked(login, function(locked) {
                    if(locked) {
                        cb('locked', login);
                    } else {
                        cb(null, login);
                    };
                });
            },
            function(login, cb) {
                clinet.gets('login_'+login,function(err,data){
                    if(!err && helpers.calculatePasswordHash(password, data.salt) == data.password_hash){
                        cb(null,login);
                    }else if(!err){
                        cb('wrong_password', login);
                    }else{
                        cb('wrong_login', login);
                    }
                    
                });
            }
        ], function(err, login) {
            var succeeded = !err;

            client.gets('login_'+login,function(err,data){
                if(succeeded){
                    data.count_failed = 0;
                    data.last_login_date = data.current_login_date;
                    data.current_login_date = new Data();
                }else{
                    data.count_failed += 1;
                }
                client.replace('login_'+login,data,function(err){
                });
            });
        });
    },

    getCurrentUser: function(login, callback) {
        client.gets('login_'+login,function(err,data){
            if(err){
                return callback(null);
            }
            callback(data);
        })
    },

    getBannedIPs: function(callback) {
        client.gets('banned_ips',function(err,data){
            callback(data);
        })
    },

    getLockedUsers: function(callback) {
        client.gets('banned_users',function(err,data){
            callback(data);
        })
    }
};

app.use(logger('dev'));
app.enable('trust proxy');
app.engine('ect', ect({ watch: true, root: __dirname + '/views', ext: '.ect' }).render);
app.set('view engine', 'ect');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ 'secret': 'isucon4-node-qualifier', resave: true, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, '../public')));

app.locals.strftime = function(format, date) {
    return strftime(format, date);
};

app.get('/', function(req, res) {
    var notice = req.session.notice;
    req.session.notice = null;

    res.render('index', { 'notice': notice });
});

app.post('/login', function(req, res) {
    helpers.attemptLogin(req, function(err, login) {
        if(err) {
            switch(err) {
            case 'locked':
                req.session.notice = 'This account is locked.';
                break;
            case 'banned':
                req.session.notice = "You're banned.";
                break;
            default:
                req.session.notice = 'Wrong username or password';
                break;
            }

            return res.redirect('/');
        }

        req.session.login = login;
        res.redirect('/mypage');
    });
});

app.get('/mypage', function(req, res) {
    helpers.getCurrentUser(req.session.login, function(login) {
        if(!login) {
            req.session.notice = "You must be logged in"
            return res.redirect('/')
        }

        client.gets('login'+req.session.login,function(err,data){
            var lastLogin = data.last_login_date;
            res.render('mypage', { 'last_login': lastLogin});
        })
    });
});

app.get('/report', function(req, res) {
    async.parallel({
        banned_ips: function(cb) {
            helpers.getBannedIPs(function(ips) {
                cb(null, ips);
            });
        },
        locked_users: function(cb) {
            helpers.getLockedUsers(function(users) {
                cb(null, users);
            });
        }
    }, function(err, result) {
        res.json(result);
    });
});

app.use(function (err, req, res, next) {
    res.status(500).send('Error: ' + err.message);
});

var server = app.listen(process.env.PORT || 8080, function() {
    console.log('Listening on port %d', server.address().port);
});


