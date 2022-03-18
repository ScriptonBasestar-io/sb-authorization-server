package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidIdentityException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.INVALID_REQUEST_FIELD_MESSAGE
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil.validateScopes
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.RedirectAuthorizationCodeRequest
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.RedirectTokenRequest
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.CodeToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType

class CallRouterRedirect(
    private val clientService: ClientService,
    private val identityService: IdentityService,
    private val converters: Converters,
    private val tokenService: TokenService,
) {
    fun redirect(redirect: RedirectAuthorizationCodeRequest): CodeToken {
        checkMissingFields(redirect)

        val clientOf = clientService.clientOf(redirect.clientId!!)
            ?: throw InvalidClientException("client for clientId you provided is null")
        if (!clientOf.redirectUris.contains(redirect.redirectUri)) {
            throw InvalidGrantException("invalid 'redirect_uri'")
        }

        with(OAuth2GrantType.AUTHORIZATION_CODE) {
            if (!clientOf.authorizedGrantTypes.contains(this)) {
                throw InvalidGrantException("Authorize not allowed: '$this'")
            }
        }

        val identityOf =
            identityService.identityOf(clientOf, redirect.username!!)
                ?: throw InvalidIdentityException("invalid identity")

        val validIdentity = identityService.validCredentials(clientOf, identityOf, redirect.password!!)
        if (!validIdentity) {
            throw InvalidIdentityException("invalid identity")
        }

        var requestedScopes = ScopeParser.parseScopes(redirect.scope)
        if (redirect.scope == null) {
            requestedScopes = clientOf.clientScopes
        }

        validateScopes(clientOf, identityOf, requestedScopes, identityService)

        val codeToken = converters.codeTokenConverter.convertToToken(
            identityOf,
            clientOf.clientId,
            redirect.redirectUri!!,
            requestedScopes
        )

        tokenService.storeCodeToken(codeToken)

        return codeToken
    }

    fun redirect(redirect: RedirectTokenRequest): TokenResponseToken {
        checkMissingFields(redirect)

        val clientOf = clientService.clientOf(redirect.clientId!!)
            ?: throw InvalidClientException("client for clientId you provided is null")
        if (!clientOf.redirectUris.contains(redirect.redirectUri)) {
            throw InvalidGrantException("invalid 'redirect_uri'")
        }

        with(OAuth2GrantType.IMPLICIT) {
            if (!clientOf.authorizedGrantTypes.contains(this)) {
                throw InvalidGrantException("Authorize not allowed: '$this'")
            }
        }

        val identityOf = identityService.identityOf(clientOf, redirect.username!!)
            ?: throw InvalidIdentityException("invalid identity")

        val validIdentity = identityService.validCredentials(clientOf, identityOf, redirect.password!!)
        if (!validIdentity) {
            throw InvalidIdentityException("invalid identity")
        }

        var requestedScopes = ScopeParser.parseScopes(redirect.scope)
        if (redirect.scope == null) {
            // @TODO: This behavior is not in the spec and should be configurable https://tools.ietf.org/html/rfc6749#section-3.3
            requestedScopes = clientOf.clientScopes
        }

        validateScopes(clientOf, identityOf, requestedScopes, identityService)

        val accessToken = converters.accessTokenConverter.convertToToken(
            identityOf,
            clientOf.clientId,
            requestedScopes,
            null
        )

        tokenService.storeAccessToken(accessToken)

        return accessToken
    }

    private fun throwMissingField(field: String): Nothing =
        throw InvalidRequestException(INVALID_REQUEST_FIELD_MESSAGE.format(field))

    private fun checkMissingFields(redirect: RedirectTokenRequest) = with(redirect) {
        when {
            clientId == null -> throwMissingField("client_id")
            username == null -> throwMissingField("username")
            password == null -> throwMissingField("password")
            redirectUri == null -> throwMissingField("redirect_uri")
            else -> this
        }
    }

    private fun checkMissingFields(redirect: RedirectAuthorizationCodeRequest) = with(redirect) {
        when {
            clientId == null -> throwMissingField("client_id")
            username == null -> throwMissingField("username")
            password == null -> throwMissingField("password")
            redirectUri == null -> throwMissingField("redirect_uri")
            else -> this
        }
    }
}
