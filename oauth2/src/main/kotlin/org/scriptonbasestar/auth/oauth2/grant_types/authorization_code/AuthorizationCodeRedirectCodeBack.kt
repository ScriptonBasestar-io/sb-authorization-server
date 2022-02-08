package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

data class AuthorizationCodeRedirectCodeBack(
    val code: String,
    val state: String,
)
