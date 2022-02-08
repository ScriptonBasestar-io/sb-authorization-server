package org.scriptonbasestar.auth.oauth2.grant_types.refresh

import org.scriptonbasestar.auth.oauth2.grant_types.ClientRequest

data class RefreshTokenRequest(
    override val clientId: String?,
    override val clientSecret: String?,
    val refreshToken: String?
) : ClientRequest {
    val grant_type = "refresh_token"
}
