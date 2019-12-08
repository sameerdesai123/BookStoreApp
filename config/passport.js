var JwtStrategy = require('passport-jwt').Strategy;
var extractJwt = require('passport-jwt').ExtractJwt;
var User = require('../models/User')
var settings = require('./settings')

module.exports = function(passport) {
    var opts = [];
    opts.jwtFromRequest = extractJwt.fromAuthHeaderWithScheme('jwt');
    opts.secretOrKey = settings.secret;
    passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
        User.findOne({ id: jwt_payload.id } , function (err, user) {
            if(err){
                return done(err, false);
            }
            if(user){
                done(null, user);
            }
            else{
                done(null, false);
            } 
    })
    }))
}