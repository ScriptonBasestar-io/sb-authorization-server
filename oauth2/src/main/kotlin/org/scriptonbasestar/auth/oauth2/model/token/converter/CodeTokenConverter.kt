package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.token.CodeToken

interface CodeTokenConverter {
    fun convertToToken(
        identity: Identity,
        clientId: String,
        redirectUri: String,
        requestedScopes: Set<String>
    ): CodeToken
}
