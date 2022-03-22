package org.scriptonbasestar.auth.oauth2.exceptions

sealed class SBSecurityException(
    message: String,
    caused: Throwable? = null
) : Exception(message, caused)

class InvalidHttpProtoException(message: String, cause: Throwable? = null) :
    SBSecurityException(message, cause)
