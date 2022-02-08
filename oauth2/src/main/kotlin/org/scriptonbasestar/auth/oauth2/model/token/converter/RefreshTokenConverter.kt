package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken

interface RefreshTokenConverter {
    fun convertToToken(refreshToken: RefreshToken): RefreshToken =
        convertToToken(refreshToken.identity, refreshToken.clientId, refreshToken.scopes)

    fun convertToToken(identity: Identity?, clientId: String, requestedScopes: Set<String>): RefreshToken
}
