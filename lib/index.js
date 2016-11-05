module.exports = {
  Strategy: require('./strategy'),
  BearerTokenError: require('oauth2-bearer-jwt-handler').BearerTokenError,
  InsufficientScopeError: require('oauth2-bearer-jwt-handler').InsufficientScopeError
};
