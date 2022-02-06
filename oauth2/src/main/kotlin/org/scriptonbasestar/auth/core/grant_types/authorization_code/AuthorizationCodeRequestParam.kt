package org.scriptonbasestar.auth.core.grant_types.authorization_code

import org.scriptonbasestar.auth.core.types.OAuth2ResponseType

data class AuthorizationCodeRequestParam(
    @Serialize
    val clientId: String,
    val redirectUri: String,
    val responseType: OAuth2ResponseType,
    val scope: String,
    val state: String,
)
