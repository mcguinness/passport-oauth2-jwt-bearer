'use strict';

const util = require('util');
const passport = require('passport-strategy');
const BearerTokenError = require('node-oauth2-bearer-jwt-handler').BearerTokenError
const JwtTokenHandler = require('node-oauth2-bearer-jwt-handler').JwtTokenHandler

function Strategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('Strategy requires a verify callback'); }
  this._verify = verify;

  if (!options.issuer) {
    throw new TypeError('options.issuer is a required argument for Strategy');
  }

  if (!options.audience) {
    throw new TypeError('options.audience is a required argument for Strategy');
  }

  if (!options.jwksUrl) {
    throw new TypeError('options.jwksUrl is a required argument for Strategy');
  }

  this._handler = new JwtTokenHandler(options);
  this._passReqToCallback = options.passReqToCallback;

  passport.Strategy.call(this);
  this.name = 'oauth2-jwt-bearer';
};

util.inherits(Strategy, passport.Strategy);


Strategy.prototype.authenticate = function(req, options) {
  var self = this;

  self._handler.verifyRequest(req, options, function(err, claims) {
    if (err) {
      return self.fail(err.challenge, err.statusCode)
    }

    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) {
        if (typeof info == 'string') {
          info = { message: info }
        }
        info = info || {};
        err = new BearerTokenError({
          realm: self._handler.realm,
          errorCode: 'invalid_token',
          description: info.message
        });
        return self.fail(err.challenge, err.statusCode);
      }
      self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, claims, verified);
    } else {
      self._verify(claims, verified);
    }
  })
};


module.exports = Strategy;
