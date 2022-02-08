package org.scriptonbasestar.auth.oauth2.token

data class TokenResponse(
    val accessToken: String,
    val tokenType: String,
    val expiresIn: Int,
    val refreshToken: String,
    val scope: String,
)
