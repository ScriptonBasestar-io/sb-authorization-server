package org.scriptonbasestar.auth.oauth2.grant_types

object ScopeParser {
    private val SCOPE_SEPARATOR = "[ +]+".toRegex()

    fun parseScopes(scopes: String?): Set<String> =
        if (!scopes.isNullOrBlank())
            scopes
                .split(SCOPE_SEPARATOR)
                .toSet()
        else setOf()
}
