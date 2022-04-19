package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.context.CallContextOut
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.HttpResponseType
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import org.scriptonbasestar.auth.oauth2.utils.ScopeParser
import org.scriptonbasestar.validation.Validation
import org.scriptonbasestar.validation.constraint.*

object ClientCredentialsGrantDefinition {
    data class ClientCredentialsRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: HttpMethod = HttpMethod.POST,

        val clientId: String,
        val clientSecret: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val scope: String?,
    )
    val clientCredentialsRequestValidation = Validation<CallContextIn> {
        CallContextIn::path required {
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""")
        }
        CallContextIn::method required {
            enum(HttpMethod.POST)
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContextIn::formParameters required {
//            hasKey("")
        }
        CallContextIn::queryParameters required {
            hasKey("client_id")
            hasKey("client_secret")
            hasKey("scope")
        }
    }
    fun clientCredentialsProcessor(
        clientCredentialsRequest: ClientCredentialsRequest,
        clientService: ClientService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): AccessToken {
        val authorizedGrantType = OAuth2GrantType.PASSWORD

        val requestedClient = clientService.findByClientId(clientCredentialsRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }
        if (!clientService.validClient(requestedClient, clientCredentialsRequest.clientSecret)) {
            throw InvalidClientException("client data is invalid")
        }
        if (!requestedClient.authorizedGrantTypes.contains(authorizedGrantType)) {
            throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
        }

        val requestedScopes = if (clientCredentialsRequest.scope != null && clientCredentialsRequest.scope.isNotBlank()) {
            ScopeParser.parseScopes(clientCredentialsRequest.scope).toSet()
        } else {
            requestedClient.clientScopes
        }

        val requestedIdentity = null

        val accessToken = accessTokenConverter.convertToToken(
            requestedIdentity,
            requestedClient.clientId,
            requestedScopes,
            refreshTokenConverter.convertToToken(
                requestedIdentity,
                requestedClient.clientId,
                requestedScopes
            )
        )

        tokenService.saveAccessToken(accessToken)

        return accessToken
    }

    fun passwordGrantCall(
        callContextIn: CallContextIn,
        clientService: ClientService,
        identityService: IdentityService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): CallContextOut<AccessToken> {
        val validResult = PasswordGrantDefinition.passwordRequestValidation.validate(callContextIn)
        if (validResult.errors.isNotEmpty()) {
            // FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val clientCredentialsRequest = ClientCredentialsRequest(
            path = callContextIn.path,
            method = callContextIn.method,
            clientId = callContextIn.formParameters["client_id"]!!,
            clientSecret = callContextIn.formParameters["client_secret"]!!,
            responseType = OAuth2ResponseType.valueOf(callContextIn.formParameters["response_type"]!!),
            scope = callContextIn.formParameters["scope"]!!,
        )
        val accessToken = clientCredentialsProcessor(
            clientCredentialsRequest = clientCredentialsRequest,
            clientService = clientService,
            accessTokenConverter = accessTokenConverter,
            refreshTokenConverter = refreshTokenConverter,
            tokenService = tokenService,
        )

        return object : CallContextOut<AccessToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: AccessToken = accessToken
        }
    }
}
