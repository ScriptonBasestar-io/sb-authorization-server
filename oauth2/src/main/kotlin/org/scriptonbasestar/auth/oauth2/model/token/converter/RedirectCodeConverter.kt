package org.scriptonbasestar.auth.oauth2.model.token.converter

import org.scriptonbasestar.auth.oauth2.model.token.RedirectCodeResponse

interface RedirectCodeConverter {
    fun convertToToken(
        clientId: String,
        requestedScopes: Set<String>,
        redirectUri: String,
    ): RedirectCodeResponse
}
