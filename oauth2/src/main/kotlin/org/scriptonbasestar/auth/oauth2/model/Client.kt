package org.scriptonbasestar.auth.oauth2.model

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class Client(
    val clientId: String,
    val clientScopes: Set<String>,
    val redirectUris: Set<String>,
    val authorizedGrantTypes: Set<OAuth2GrantType>
)
