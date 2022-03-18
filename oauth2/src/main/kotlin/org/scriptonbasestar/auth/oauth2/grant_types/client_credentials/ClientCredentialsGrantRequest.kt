package org.scriptonbasestar.auth.oauth2.grant_types.client_credentials

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class ClientCredentialsGrantRequest(
    override val clientId: String?,
    override val clientSecret: String?
) : ClientRequest {
    val grant_tyep = OAuth2GrantType.CLIENT_CREDENTIALS
}
