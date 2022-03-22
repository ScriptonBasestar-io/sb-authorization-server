package org.scriptonbasestar.auth.oauth2.grant_types.implicit

import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

data class ImplicitGrantRequest(
    val clientId: String?,
    val clientSecret: String?,
    val scope: String?,
    val grantType: OAuth2GrantType = OAuth2GrantType.IMPLICIT
)
