package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.token.RedirectCodeResponse
import java.time.Instant
import java.util.*

class UUIDRedirectCodeConverter(
    private val codeTokenExpireInSeconds: Int = 300
) : RedirectCodeConverter {
    override fun convertToToken(
        clientId: String,
        requestedScopes: Set<String>,
        redirectUri: String
    ): RedirectCodeResponse {
        return RedirectCodeResponse(
            Instant.now().plusSeconds(codeTokenExpireInSeconds.toLong()),
            UUID.randomUUID().toString(),
            clientId,
            redirectUri,
        )
    }
}
