package org.scriptonbasestar.auth.oauth2.grant_types.password

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class PasswordGrantRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val username: String,
    val password: String,
    val scope: String?
) : ClientRequest {
    val grant_type = OAuth2GrantType.PASSWORD
}
