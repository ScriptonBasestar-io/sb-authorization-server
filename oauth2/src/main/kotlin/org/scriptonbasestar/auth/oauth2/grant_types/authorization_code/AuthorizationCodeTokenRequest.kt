package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class AuthorizationCodeTokenRequest(
    val clientId: String,
    val clientSecret: String,

    val grantType: OAuth2GrantType = OAuth2GrantType.AUTHORIZATION_CODE,
    val code: String,
    val redirectUri: String,
)
