package org.scriptonbasestar.auth.oauth2.grant_types.implicit

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

@Deprecated("implicit grant is not recommended")
data class ImplicitGrantRequest(
    override val clientId: String?,
    override val clientSecret: String?,
): ClientRequest {
    val grantType = OAuth2GrantType.IMPLICIT
}
