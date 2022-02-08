package org.scriptonbasestar.auth.oauth2.exceptions

open class SBOAuthException(
//    val error: OAuthError,
    message: String,
    cause: Throwable,
) : Exception(message, cause)
