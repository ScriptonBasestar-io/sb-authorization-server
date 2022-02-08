package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.CodeToken
import java.time.Instant
import java.util.*

class UUIDCodeTokenConverter(
    private val codeTokenExpireInSeconds: Int = 300
) : CodeTokenConverter {
    override fun convertToToken(
        identity: Identity,
        clientId: String,
        redirectUri: String,
        requestedScopes: Set<String>
    ): CodeToken {
        return CodeToken(
            UUID.randomUUID().toString(),
            Instant.now().plusSeconds(codeTokenExpireInSeconds.toLong()),
            identity,
            clientId,
            redirectUri,
            requestedScopes
        )
    }
}
