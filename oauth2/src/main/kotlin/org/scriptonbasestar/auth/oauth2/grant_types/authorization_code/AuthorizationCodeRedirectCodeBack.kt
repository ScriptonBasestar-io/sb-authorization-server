package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest

data class AuthorizationCodeRedirectCodeBack(
    val code: String,
    val state: String,
)
