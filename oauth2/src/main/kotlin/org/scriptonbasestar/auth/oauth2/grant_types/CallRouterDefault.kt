package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.endpoints.ClientCredentialsRequest
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidScopeException
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeRequest
import org.scriptonbasestar.auth.oauth2.grant_types.password_credentials.PasswordGrantRequest
import org.scriptonbasestar.auth.oauth2.grant_types.refresh.RefreshTokenRequest
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.TokenInfo

fun GrantingCall.grantPassword() = granter("password") {
    val accessToken = authorize(
        PasswordGrantRequest(
            callContext.formParameters["client_id"],
            callContext.formParameters["client_secret"],
            callContext.formParameters["username"],
            callContext.formParameters["password"],
            callContext.formParameters["scope"]
        )
    )

    callContext.respondHeader("Cache-Control", "no-store")
    callContext.respondHeader("Pragma", "no-cache")
    callContext.respondJson(accessTokenResponder.createResponse(accessToken))
}

fun GrantingCall.grantClientCredentials() = granter("client_credentials") {
    val accessToken = authorize(
        ClientCredentialsRequest(
            callContext.formParameters["client_id"],
            callContext.formParameters["client_secret"],
            callContext.formParameters["scope"]
        )
    )

    callContext.respondHeader("Cache-Control", "no-store")
    callContext.respondHeader("Pragma", "no-cache")
    callContext.respondJson(accessTokenResponder.createResponse(accessToken))
}

fun GrantingCall.grantRefreshToken() = granter("refresh_token") {
    val accessToken = refresh(
        RefreshTokenRequest(
            callContext.formParameters["client_id"],
            callContext.formParameters["client_secret"],
            callContext.formParameters["refresh_token"]
        )
    )

    callContext.respondHeader("Cache-Control", "no-store")
    callContext.respondHeader("Pragma", "no-cache")
    callContext.respondJson(accessTokenResponder.createResponse(accessToken))
}

fun GrantingCall.grantAuthorizationCode() = granter("authorization_code") {
    val accessToken = authorize(
        AuthorizationCodeRequest(
            callContext.formParameters["client_id"],
            callContext.formParameters["client_secret"],
            callContext.formParameters["code"],
            callContext.formParameters["redirect_uri"]
        )
    )

    callContext.respondHeader("Cache-Control", "no-store")
    callContext.respondHeader("Pragma", "no-cache")
    callContext.respondJson(accessTokenResponder.createResponse(accessToken))
}

internal val INVALID_REQUEST_FIELD_MESSAGE = "'%s' field is missing"

fun GrantingCall.validateScopes(
    client: Client,
    identity: Identity,
    requestedScopes: Set<String>
) {
    val scopesAllowed = scopesAllowed(client.clientScopes, requestedScopes)
    if (!scopesAllowed) {
        throw InvalidScopeException("Scopes not allowed: ${requestedScopes.minus(client.clientScopes)}")
    }

    val allowedScopes = identityService.allowedScopes(client, identity, requestedScopes)

    val ivalidScopes = requestedScopes.minus(allowedScopes)
    if (ivalidScopes.isNotEmpty()) {
        throw InvalidScopeException("Scopes not allowed: $ivalidScopes")
    }
}

fun GrantingCall.tokenInfo(accessToken: String): TokenInfo {
    val storedAccessToken = tokenStore.accessToken(accessToken) ?: throw InvalidGrantException("token is not valid")
    val client = clientService.clientOf(storedAccessToken.clientId) ?: throw InvalidClientException("client for clientId you provided is null")
    val identity = storedAccessToken.identity?.let { identityService.identityOf(client, it.username) }

    return TokenInfo(
        identity,
        client,
        storedAccessToken.scopes
    )
}

fun GrantingCall.throwExceptionIfUnverifiedClient(clientRequest: ClientRequest) {
    val clientId = clientRequest.clientId
        ?: throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("client_id"))

    val clientSecret = clientRequest.clientSecret
        ?: throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("client_secret"))

    val client = clientService.clientOf(clientId) ?: throw InvalidClientException("client for clientId you provided is null")

    if (!clientService.validClient(client, clientSecret)) {
        throw InvalidClientException("client is not valid")
    }
}

fun GrantingCall.scopesAllowed(clientScopes: Set<String>, requestedScopes: Set<String>): Boolean {
    return clientScopes.containsAll(requestedScopes)
}
