package org.scriptonbasestar.auth.oauth2.model

data class TokenInfo(
    val identity: Identity?,
    val client: Client,
    val scopes: Set<String>
)
