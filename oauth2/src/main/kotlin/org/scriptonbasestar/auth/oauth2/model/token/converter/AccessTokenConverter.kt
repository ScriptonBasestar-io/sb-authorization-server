package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken

interface AccessTokenConverter {
    fun convertToToken(
        identity: Identity?,
        clientId: String,
        requestedScopes: Set<String>,
        refreshToken: RefreshToken?
    ): TokenResponseToken
}
