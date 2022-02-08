package org.scriptonbasestar.auth.oauth2.model.token

interface AccessTokenResponder {
    fun createResponse(accessToken: AccessToken): Map<String, Any?>
}
