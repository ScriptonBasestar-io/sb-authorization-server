package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

class RedirectAuthorizationCodeRequest(
    val clientId: String?,
    val redirectUri: String?,
    val username: String?,
    val password: String?,
    val scope: String?
)
