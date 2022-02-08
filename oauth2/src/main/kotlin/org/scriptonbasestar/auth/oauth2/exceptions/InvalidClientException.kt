package org.scriptonbasestar.auth.oauth2.exceptions

class InvalidClientException(message: String, cause: Throwable? = null) :
    SBOAuthException(OAuthError.INVALID_CLIENT, message, cause)
