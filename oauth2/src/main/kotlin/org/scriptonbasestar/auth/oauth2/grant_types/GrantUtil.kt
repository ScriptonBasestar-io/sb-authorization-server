package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidScopeException
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService

object GrantUtil {

    const val INVALID_REQUEST_FIELD_MESSAGE = "'%s' field is missing"

    fun throwExceptionIfUnverifiedClient(clientRequest: ClientRequest, clientService: ClientService) {
        val clientId = clientRequest.clientId
            ?: throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("client_id"))

        val clientSecret = clientRequest.clientSecret
            ?: throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format("client_secret"))

        val client =
            clientService.clientOf(clientId) ?: throw InvalidClientException("client for clientId you provided is null")

        if (!clientService.validClient(client, clientSecret)) {
            throw InvalidClientException("client is not valid")
        }
    }

    fun validateScopes(
        client: Client,
        identity: Identity,
        requestedScopes: Set<String>,
        identityService: IdentityService,
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

    fun scopesAllowed(clientScopes: Set<String>, requestedScopes: Set<String>): Boolean {
        return clientScopes.containsAll(requestedScopes)
    }
}
