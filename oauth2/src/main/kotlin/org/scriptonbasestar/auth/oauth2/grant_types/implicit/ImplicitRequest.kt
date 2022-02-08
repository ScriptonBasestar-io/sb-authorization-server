package org.scriptonbasestar.auth.oauth2.grant_types.implicit

import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType

data class ImplicitRequest(
    val clientId: String,
    val redirectUri: String,
    val responseType: OAuth2ResponseType = OAuth2ResponseType.TOKEN,
    val scope: String,
    val lang: String? = null,
)
