package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class AuthorizationCodeGrantRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val code: String?,
    val redirectUri: String?
) : ClientRequest {
    val grant_type = OAuth2GrantType.AUTHORIZATION_CODE
}
