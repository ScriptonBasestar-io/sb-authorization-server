package org.scriptonbasestar.auth.oauth2.exceptions

open class InvalidGrantException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_GRANT, message, cause)
