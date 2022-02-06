package org.scriptonbasestar.auth.core.exceptions

open class SBOAuthException(
//    val error: OAuthError,
    message: String,
    cause: Throwable,
) : Exception(message, cause)
