package org.scriptonbasestar.auth.oauth2.grant_types.password_credentials

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class PasswordRequestParam(
    val clientId: String,
    val clientSecret: String?,

    val username: String,
    val password: String,

    val grantType: OAuth2GrantType = OAuth2GrantType.PASSWORD
)
