package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest

data class AuthorizationCodeRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val code: String?,
    val redirectUri: String?
) : ClientRequest {
    val grant_type = "authorization_code"
}
