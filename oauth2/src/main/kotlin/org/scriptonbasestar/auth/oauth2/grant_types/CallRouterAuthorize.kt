package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidIdentityException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.INVALID_REQUEST_FIELD_MESSAGE
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.throwExceptionIfUnverifiedClient
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.validateScopes
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeGrantRequest
import org.scriptonbasestar.auth.oauth2.grant_types.password.PasswordGrantRequest
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

class CallRouterAuthorize(
    private val clientService: ClientService,
    private val identityService: IdentityService,
    private val converters: Converters,
    private val tokenService: TokenService,
) {
    /**
     * @throws InvalidIdentityException
     * @throws InvalidClientException
     * @throws InvalidScopeException
     */
    fun authorize(passwordGrantRequest: PasswordGrantRequest): TokenResponseToken {
        throwExceptionIfUnverifiedClient(passwordGrantRequest, clientService)

        if (passwordGrantRequest.username == null) {
            throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("username"))
        }

        if (passwordGrantRequest.password == null) {
            throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("password"))
        }

        val requestedClient = clientService.clientOf(passwordGrantRequest.clientId!!)
            ?: throw InvalidClientException("client for clientId you provided is null")

        val authorizedGrantType = OAuth2GrantType.PASSWORD
        if (!requestedClient.authorizedGrantTypes.contains(authorizedGrantType)) {
            throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
        }

        val requestedIdentity = identityService.identityOf(
            requestedClient, passwordGrantRequest.username
        )

        if (requestedIdentity == null || !identityService.validCredentials(
                requestedClient,
                requestedIdentity,
                passwordGrantRequest.password
            )
        ) {
            throw InvalidIdentityException("client is not valid")
        }

        var requestedScopes = ScopeParser.parseScopes(passwordGrantRequest.scope)
            .toSet()

        if (passwordGrantRequest.scope == null) {
            requestedScopes = requestedClient.clientScopes
        }

        validateScopes(requestedClient, requestedIdentity, requestedScopes, identityService)

        val accessToken = converters.accessTokenConverter.convertToToken(
            requestedIdentity,
            requestedClient.clientId,
            requestedScopes,
            converters.refreshTokenConverter.convertToToken(
                requestedIdentity,
                requestedClient.clientId,
                requestedScopes
            )
        )

        tokenService.storeAccessToken(accessToken)

        return accessToken
    }

    fun authorize(authorizationCodeRequest: AuthorizationCodeGrantRequest): TokenResponseToken {
        throwExceptionIfUnverifiedClient(authorizationCodeRequest, clientService)

        if (authorizationCodeRequest.code == null) {
            throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("code"))
        }

        if (authorizationCodeRequest.redirectUri == null) {
            throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("redirect_uri"))
        }

        val consumeCodeToken = tokenService.consumeCodeToken(authorizationCodeRequest.code)
            ?: throw InvalidGrantException("token for ${authorizationCodeRequest.code} must not null")

        if (consumeCodeToken.redirectUri != authorizationCodeRequest.redirectUri || consumeCodeToken.clientId != authorizationCodeRequest.clientId) {
            throw InvalidGrantException("invalid grant")
        }

        val accessToken = converters.accessTokenConverter.convertToToken(
            consumeCodeToken.identity,
            consumeCodeToken.clientId,
            consumeCodeToken.scopes,
            converters.refreshTokenConverter.convertToToken(
                consumeCodeToken.identity,
                consumeCodeToken.clientId,
                consumeCodeToken.scopes
            )
        )

        tokenService.storeAccessToken(accessToken)

        return accessToken
    }

    fun authorize(clientCredentialsRequest: ClientCredentialsRequest): TokenResponseToken {
        throwExceptionIfUnverifiedClient(clientCredentialsRequest, clientService)

        val requestedClient = clientService.clientOf(clientCredentialsRequest.clientId!!)
            ?: throw InvalidClientException("client for clientId you provided is null")

        val scopes = clientCredentialsRequest.scope
            ?.let { ScopeParser.parseScopes(it).toSet() }
            ?: requestedClient.clientScopes

        val accessToken = converters.accessTokenConverter.convertToToken(
            identity = null,
            clientId = clientCredentialsRequest.clientId,
            requestedScopes = scopes,
            refreshToken = converters.refreshTokenConverter.convertToToken(
                identity = null,
                clientId = clientCredentialsRequest.clientId,
                requestedScopes = scopes
            )
        )

        tokenService.storeAccessToken(accessToken)

        return accessToken
    }
}
