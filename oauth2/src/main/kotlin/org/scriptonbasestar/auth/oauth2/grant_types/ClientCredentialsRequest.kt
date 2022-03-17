package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest

data class ClientCredentialsRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val scope: String?
) : ClientRequest {
    val grant_type = "client_credentials"
}
