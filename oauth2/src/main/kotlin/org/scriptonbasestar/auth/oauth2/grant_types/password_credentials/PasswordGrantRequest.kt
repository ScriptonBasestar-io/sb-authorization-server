package org.scriptonbasestar.auth.oauth2.grant_types.password_credentials

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest

data class PasswordGrantRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val username: String?,
    val password: String?,
    val scope: String?
) : ClientRequest {
    val grant_type = "password"
}
