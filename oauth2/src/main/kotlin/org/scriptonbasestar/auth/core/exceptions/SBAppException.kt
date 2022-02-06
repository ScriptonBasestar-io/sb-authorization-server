package org.scriptonbasestar.auth.core.exceptions

open class SBAppException(
    message: String,
    cause: Throwable,
) : RuntimeException(message, cause)
