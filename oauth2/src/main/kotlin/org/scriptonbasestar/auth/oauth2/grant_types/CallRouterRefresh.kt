package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.INVALID_REQUEST_FIELD_MESSAGE
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.throwExceptionIfUnverifiedClient
import org.scriptonbasestar.auth.oauth2.grant_types.refresh_token.RefreshTokenRequest
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

class CallRouterRefresh(
    private val clientService: ClientService,
    private val identityService: IdentityService,
    private val converters: Converters,
    private val tokenService: TokenService,
) {
    fun refresh(refreshTokenRequest: RefreshTokenRequest): TokenResponseToken {
        throwExceptionIfUnverifiedClient(refreshTokenRequest, clientService)

        if (refreshTokenRequest.refreshToken == null) {
            throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("refresh_token"))
        }

        val refreshToken =
            tokenService.refreshToken(refreshTokenRequest.refreshToken) ?: throw InvalidGrantException("invalid grant")

        if (refreshToken.clientId != refreshTokenRequest.clientId) {
            throw InvalidGrantException("invalid grant")
        }

        val client = clientService.clientOf(refreshToken.clientId)
            ?: throw InvalidClientException("client for clientId you provided is null")

        val authorizedGrantType = OAuth2GrantType.REFRESH_TOKEN
        if (!client.authorizedGrantTypes.contains(authorizedGrantType)) {
            throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
        }

        val accessToken = converters.accessTokenConverter.convertToToken(
            refreshToken.identity,
            refreshToken.clientId,
            refreshToken.scopes,
            converters.refreshTokenConverter.convertToToken(refreshToken)
        )

        tokenService.storeAccessToken(accessToken)

        return accessToken
    }
}
