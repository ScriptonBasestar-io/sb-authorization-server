package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import java.time.Instant
import java.util.*

class UUIDRefreshTokenConverter(
    private val refreshTokenExpireInSeconds: Int = 86400
) : RefreshTokenConverter {
    override fun convertToToken(identity: Identity?, clientId: String, requestedScopes: Set<String>): RefreshToken {
        return RefreshToken(
            UUID.randomUUID().toString(),
            Instant.now().plusSeconds(refreshTokenExpireInSeconds.toLong()),
            identity,
            clientId,
            requestedScopes
        )
    }
}
