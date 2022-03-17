package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.types.AuthorizedGrantType
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.grant_types.refresh.RefreshTokenRequest
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken

fun GrantingCall.refresh(refreshTokenRequest: RefreshTokenRequest): AccessToken {
    throwExceptionIfUnverifiedClient(refreshTokenRequest)

    if (refreshTokenRequest.refreshToken == null) {
        throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("refresh_token"))
    }

    val refreshToken = tokenStore.refreshToken(refreshTokenRequest.refreshToken) ?: throw InvalidGrantException("invalid grant")

    if (refreshToken.clientId != refreshTokenRequest.clientId) {
        throw InvalidGrantException("invalid grant")
    }

    val client = clientService.clientOf(refreshToken.clientId) ?: throw InvalidClientException("client for clientId you provided is null")

    val authorizedGrantType = AuthorizedGrantType.REFRESH_TOKEN
    if (!client.authorizedGrantTypes.contains(authorizedGrantType)) {
        throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
    }

    val accessToken = converters.accessTokenConverter.convertToToken(
        refreshToken.identity,
        refreshToken.clientId,
        refreshToken.scopes,
        converters.refreshTokenConverter.convertToToken(refreshToken)
    )

    tokenStore.storeAccessToken(accessToken)

    return accessToken
}
