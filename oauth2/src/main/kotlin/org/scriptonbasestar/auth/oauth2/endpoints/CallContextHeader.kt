package org.scriptonbasestar.auth.oauth2.endpoints

fun CallContext.headerCaseInsensitive(key: String) = headers
    .filter { it.key.equals(key, true) }
    .values
    .firstOrNull()
