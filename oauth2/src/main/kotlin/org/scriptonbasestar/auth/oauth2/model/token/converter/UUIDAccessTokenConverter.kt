package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import java.time.Instant
import java.util.*

class UUIDAccessTokenConverter(
    private val accessTokenExpireInSeconds: Int = 3600
) : AccessTokenConverter {

    override fun convertToToken(
        identity: Identity?,
        clientId: String,
        requestedScopes: Set<String>,
        refreshToken: RefreshToken?
    ): TokenResponseToken {
        return TokenResponseToken(
            UUID.randomUUID().toString(),
            "bearer",
            Instant.now().plusSeconds(accessTokenExpireInSeconds.toLong()),
            identity,
            clientId,
            requestedScopes,
            refreshToken
        )
    }
}
