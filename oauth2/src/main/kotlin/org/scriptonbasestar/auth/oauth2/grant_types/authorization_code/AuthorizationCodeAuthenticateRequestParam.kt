package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType

data class AuthorizationCodeAuthenticateRequestParam(
    val clientId: String,

    val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
    val redirectUri: String,
    val scope: String,
    val state: String,
)
