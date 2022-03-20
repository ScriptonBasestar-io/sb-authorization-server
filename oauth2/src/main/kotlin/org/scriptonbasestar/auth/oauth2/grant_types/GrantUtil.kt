package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.exceptions.InvalidScopeException
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService

object GrantUtil {

//    fun throwExceptionIfUnverifiedClient(
//        clientId: String,
//        clientSecret: String,
//        clientService: clientService
//    ) {
//        val client = clientService.findByClientId(clientId).orElseThrow {
//            InvalidClientException("client for clientId you provided is null")
//        }
//
//        if (!clientService.validClient(client, clientSecret)) {
//            throw InvalidClientException("client is not valid")
//        }
//    }

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
