package org.scriptonbasestar.auth.oauth2.model.token.converter

data class Converters(
    val accessTokenConverter: AccessTokenConverter,
    val refreshTokenConverter: RefreshTokenConverter,
    val codeTokenConverter: CodeTokenConverter
)
