package org.scriptonbasestar.auth.oauth2.exceptions

open class SBAppException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
