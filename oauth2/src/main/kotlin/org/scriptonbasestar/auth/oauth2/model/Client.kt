package org.scriptonbasestar.auth.oauth2.model

data class Client(
    val clientId: String,
    val clientScopes: Set<String>,
    val redirectUris: Set<String>,
    val authorizedGrantTypes: Set<String>
)
