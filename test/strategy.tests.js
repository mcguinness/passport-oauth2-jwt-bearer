var chai = require('chai');
chai.use(require('chai-passport-strategy'));
var assert = chai.assert;
var expect = chai.expect;
var sinon = require('sinon');
var nock = require('nock');
var path = require('path');
var fs = require('fs');
var Strategy = require('../lib/strategy.js');

describe('Strategy', function() {

  var baseUrl = 'https://example.oktapreview.com';
  var jwksPath = '/oauth2/v1/keys';

  describe('#id_token', function() {

    var id_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkM0TmdMMlFIVHpvRVJfbzEzTGJza2pYWk1RV1FoUVRZZzNvdFBHR1pHWFkifQ.eyJzdWIiOiIwMHU1aXZzdnI1MzFVNWRoajBoNyIsIm5hbWUiOiJLYXJsIE1jR3Vpbm5lc3MiLCJsb2NhbGUiOiJlbi1VUyIsImVtYWlsIjoia21jZ3Vpbm5lc3NAb2t0YS5jb20iLCJ2ZXIiOjEsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5va3RhcHJldmlldy5jb20iLCJhdWQiOiJBTlJaaHlEaDhIQkZONWFiTjZSZyIsImlhdCI6MTQ2MDMxMzUxMiwiZXhwIjoxNDYwMzE3MTEyLCJqdGkiOiJGekFqdS14RVhaa2ZWSTJudmstdiIsImFtciI6WyJwd2QiXSwiaWRwIjoiMDBvNWl2c3ZxbEpTSlZCbWUwaDciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrbWNndWlubmVzc0Bva3RhLmNvbSIsImdpdmVuX25hbWUiOiJLYXJsIiwiZmFtaWx5X25hbWUiOiJNY0d1aW5uZXNzIiwiem9uZWluZm8iOiJBbWVyaWNhL0xvc19BbmdlbGVzIiwidXBkYXRlZF9hdCI6MTQ1NzgzNDk1MiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF1dGhfdGltZSI6MTQ2MDMxMzUxMn0.cxx2NHLcN8-Fabbw3GfcfQYJut0s6dvhPBokvL2eZlXEz1PlC6uronOT55E8qLf4PgQbuSqiW9HQHtp6ollRGJzPGzjEvociHh9LnHmK8p2EUBS_JcddXuH2UxYbCFo45lp-wMhHUEQGaQaMzuNscIju2Xy93Dv9rCsl826hE1vNZAoiYpvLBlGF2rUE_w4RmZSIzbDYBe5ueBtTzM1KaLgIXExNXqHhsyHv2MZV5Mz0UUcg66P2HwEgDWoHHZQhx11u57-3Bd_S1PxIcM-EAtMhnj0onr588muaACgeVAh8P3-kK3MvzqhHBIMQCwUbmDO4b5DYcj3xaYVHq62Raw';
    var issuer = 'https://example.oktapreview.com';
    var kid ='C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY';
    var expiresAt = 1460313512;
    var audience = 'ANRZhyDh8HBFN5abN6Rg';
    var subject = '00u5ivsvr531U5dhj0h7';
    var email = 'kmcguinness@okta.com';
    var strategy = new Strategy({
      issuer: issuer,
      audience: audience,
      realm: 'OIDC',
      jwksUrl: baseUrl + jwksPath,
    }, function(token, done) {
      // done(err, user, info)
      return done(null, token);
    });
    var clock;

    beforeEach(function() {
      clock = sinon.useFakeTimers((expiresAt - 60) * 1000);
      nock.cleanAll();
      nock(baseUrl)
        .get(jwksPath)
        .replyWithFile(200, path.join(__dirname, 'keys.json'));
    });

    afterEach(function() {
      clock.restore();
    })

    describe('token request', function() {

      describe('with valid token', function() {

        it('should have subject, issuer, and audience claims', function(done) {
          chai.passport.use(strategy)
            .success(function(user, info) {
              expect(user).to.be.an.object;
              expect(user.sub).to.equal(subject);
              expect(user.iss).to.equal(issuer);
              expect(user.aud).to.equal(audience);
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + id_token;
            })
            .authenticate();
        });

      });

      describe('with expired token', function() {

        it('should fail with invalid_token challenge', function(done) {
          clock.restore();
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_token", ' +
                'error_description="The token is expired", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.4"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + id_token;
            })
            .authenticate();
        });

      });

      describe('with missing scheme', function() {

        it('should fail with invalid_request challenge', function(done) {
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_request", ' +
                'error_description="Request must specify a valid scheme and token for authorization header", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-2.1"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'MISSING';
            })
            .authenticate();
        });

      });

      describe('with missing kid header parameter', function() {

        it('should fail with invalid_token challenge', function(done) {
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_token", ' +
                'error_description="The token must specify a "kid" (Key ID) header parameter", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Dt2W1GtOLnnqf4-PUr5Ns_9BuLLmwpWO5zBwN4fokX4';
            })
            .authenticate();
        });

      });

      describe('with invalid JWT', function() {

        it('should fail with invalid_token challenge', function(done) {
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_token", ' +
                'error_description="The token is not a valid JSON Web Token (JWT)", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER WRONG';
            })
            .authenticate();
        });

      });

    });

  });

  describe('#access_token', function() {

    var issuer = 'https://example.oktapreview.com/as/orsKMQsSWQvzyPXbz0NY';
    var access_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjdFd0I2elR3NFYxSHRzVFRpZFlvcVpJNEZoeHJMM3M2Y283NmpuTFBKLWsifQ.eyJ2ZXIiOjEsImp0aSI6IkFULk1ydXZ0OHVUT1R2dThrMi11LTZaZDJsb3kyNG9PZkJuWFhEalhlQW5nV2ciLCJpc3MiOiJodHRwczovL2V4YW1wbGUub2t0YXByZXZpZXcuY29tL2FzL29yc0tNUXNTV1F2enlQWGJ6ME5ZIiwiYXVkIjoiQU5SWmh5RGg4SEJGTjVhYk42UmciLCJzdWIiOiIwMHU1aXZzdnI1MzFVNWRoajBoNyIsImlhdCI6MTQ2ODk0NTgzNCwiZXhwIjoxNDY4OTQ5NDM0LCJjaWQiOiJBTlJaaHlEaDhIQkZONWFiTjZSZyIsInVpZCI6IjAwdTVpdnN2cjUzMVU1ZGhqMGg3Iiwic2NwIjpbIm9wZW5pZCIsImVtYWlsIiwicHJvZmlsZSIsImFkZHJlc3MiLCJwaG9uZSJdLCJzdWJBbHROYW1lIjoia21jZ3Vpbm5lc3NAb2t0YS5jb20ifQ.f6RMEjYhjIMnxJr1xgJWBz_igYdN3hxxDPSOODUsJxD_Ud_w5tKVVLIAKIM70hZ1DFLytaIoRI71EvuKB3uUMh5AR0N_gvLZnamKdrKl9r5RD1WLbUL7sKm378b4KWW2n1gqZBXAn9Se_mdk1j0_6Dq63sc6qhjSn40VEINU6RV7uwP4OGo0RdFaVWGo14biMrxgGa38rlZc_k-p0fd8zL6nw4W5myrikqW-mF2Xf55B05Fec2GelBcqoyarnF5EiMU-6G4tO1TQC5LM8J0glqhRAkXBOjpAK8eTAKWYpIQY_7MuIt5VCvVQ9anBGJ2GMQWm_oy9thZaeItAhxthPw';
    var kid = '7EwB6zTw4V1HtsTTidYoqZI4FhxrL3s6co76jnLPJ-k';
    var expiresAt = 1468949434;
    var audience = 'ANRZhyDh8HBFN5abN6Rg';
    var subject = '00u5ivsvr531U5dhj0h7';
    var email = 'kmcguinness@okta.com';
    var strategy = new Strategy({
      issuer: issuer,
      audience: audience,
      realm: 'OAUTH',
      jwksUrl: baseUrl + jwksPath
    }, function(token, done) {
      // done(err, user, info)
      return done(null, token);
    });
    var clock;

    beforeEach(function() {
      clock = sinon.useFakeTimers((expiresAt - 60) * 1000);
      nock.cleanAll();
      nock(baseUrl)
        .get(jwksPath)
        .replyWithFile(200, path.join(__dirname, 'keys.json'));
    });

    afterEach(function() {
      clock.restore();
    })

    describe('token request', function() {

      describe('with valid token', function() {

        it('should have subject, issuer, and audience claims', function(done) {
          chai.passport.use(strategy)
            .success(function(user, info) {
              expect(user).to.be.an.object;
              expect(user.sub).to.equal(subject);
              expect(user.iss).to.equal(issuer);
              expect(user.aud).to.equal(audience);
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + access_token;
            })
            .authenticate();
        });

        it('should have scopes', function(done) {
          chai.passport.use(strategy)
            .success(function(user, info) {
              expect(user).to.be.an.object;
              expect(user.sub).to.equal(subject);
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + access_token;
            })
            .authenticate({scopes: ['profile', 'email']});
        });

        it('should challenge for scopes', function(done) {
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OAUTH", error="insufficient_scope", ' +
                'error_description="Insufficient scope for this resource", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-3", scope="missing"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + access_token;
            })
            .authenticate({scopes: ['missing']});
        });
      });

      describe('with expired token', function() {

        it('should fail with invalid_token challenge', function(done) {
          clock.restore();
          chai.passport.use(strategy)
            .fail(function(challenge) {
              expect(challenge).to.be.a.string;
              expect(challenge).to.equal('Bearer realm="OAUTH", error="invalid_token", ' +
                'error_description="The token is expired", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.4"');
              done();
            })
            .req(function(req) {
              req.headers.authorization = 'BEARER ' + access_token;
            })
            .authenticate();
        });

      });

    });

  });

});
