package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
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
    ): AccessToken {
        return AccessToken(
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
