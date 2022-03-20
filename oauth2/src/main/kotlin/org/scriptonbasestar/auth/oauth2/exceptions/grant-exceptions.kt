package org.scriptonbasestar.auth.oauth2.exceptions

open class InvalidClientException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_CLIENT, message, cause)

open class InvalidGrantException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_GRANT, message, cause)

open class InvalidIdentityException(message: String, cause: Throwable? = null) :
    InvalidGrantException(message, cause)

open class InvalidRequestException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_REQUEST, message, cause)

// "Scopes not allowed: $notAllowedScopes"
open class InvalidScopeException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_SCOPE, message, cause)
