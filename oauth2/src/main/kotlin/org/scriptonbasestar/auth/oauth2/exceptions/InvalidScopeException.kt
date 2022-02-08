package org.scriptonbasestar.auth.oauth2.exceptions

// "Scopes not allowed: $notAllowedScopes"
class InvalidScopeException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_SCOPE, message, cause)
