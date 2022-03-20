package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class ClientCredentialsRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val scope: String?
) : ClientRequest {
    val grantType = OAuth2GrantType.CLIENT_CREDENTIALS
}
