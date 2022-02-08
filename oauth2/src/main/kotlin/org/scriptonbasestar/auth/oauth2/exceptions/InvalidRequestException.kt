package org.scriptonbasestar.auth.oauth2.exceptions

class InvalidRequestException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_REQUEST, message, cause)
