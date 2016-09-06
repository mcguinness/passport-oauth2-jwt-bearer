module.exports = {
  Strategy: require('./strategy'),
  BearerTokenError: require('node-oauth2-bearer-jwt-handler').BearerTokenError,
  InsufficientScopeError: require('node-oauth2-bearer-jwt-handler').InsufficientScopeError
};
