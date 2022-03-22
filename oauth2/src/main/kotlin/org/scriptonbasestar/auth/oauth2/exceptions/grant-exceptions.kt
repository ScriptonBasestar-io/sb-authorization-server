package org.scriptonbasestar.auth.oauth2.exceptions

sealed class SBOAuthException(
    val error: OAuthError,
    message: String,
    caused: Throwable? = null,
) : Exception(message, caused)

class InvalidClientException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_CLIENT, message, cause)

open class InvalidGrantException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_GRANT, message, cause)

class InvalidIdentityException(message: String, cause: Throwable? = null) :
    InvalidGrantException(message, cause)

class InvalidRequestException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_REQUEST, message, cause)

// "Scopes not allowed: $notAllowedScopes"
class InvalidScopeException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_SCOPE, message, cause)
