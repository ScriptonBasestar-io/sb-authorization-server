package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.context.CallContextOut
import org.scriptonbasestar.auth.oauth2.exceptions.*
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

object RefreshTokenGrantDefinition {
    data class RefreshTokenRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: HttpMethod = HttpMethod.POST,

        val clientId: String,
        val clientSecret: String,

        val refreshToken: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val refreshTokenRequestValidation = Validation<CallContextIn> {
        CallContextIn::path required {
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""") hint ""
        }
        CallContextIn::method required {
            enum(HttpMethod.POST) hint ""
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded") hint ""
        }
        CallContextIn::formParameters required {
//            hasKey("")
        }
        CallContextIn::queryParameters required {
            hasKeyValueNotBlank("client_id") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "client_id"
                )
            )
            hasKeyValueNotBlank("client_secret") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "client_id"
                )
            )
            hasKeyValueNotBlank("refresh_token") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "refresh_token"
                )
            )
            hasKey("scope")
        }
    }

    fun refreshTokenRequestProcess(
        refreshTokenRequest: RefreshTokenRequest,
        clientService: ClientService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): AccessToken {
        val authorizedGrantType = OAuth2GrantType.REFRESH_TOKEN
        val requestedClient = clientService.findByClientId(refreshTokenRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }

        if (!requestedClient.authorizedGrantTypes.contains(authorizedGrantType)) {
            throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
        }

        if (!clientService.validClient(requestedClient, refreshTokenRequest.clientSecret)) {
            throw InvalidClientException("client data is invalid")
        }
        val refreshToken =
            tokenService.refreshToken(refreshTokenRequest.refreshToken) ?: throw InvalidGrantException("invalid grant")

        if (refreshToken.clientId != refreshTokenRequest.clientId) {
            throw InvalidGrantException("invalid grant")
        }

//        scope가 원래 access token의 scope보다 넓을 수 없음
        val requestedScopes = if (refreshTokenRequest.scope != null && refreshTokenRequest.scope.isNotBlank()) {
            ScopeParser.parseScopes(refreshTokenRequest.scope).toSet()
        } else {
            requestedClient.clientScopes
        }

        val requestedIdentity = null

        val accessToken = accessTokenConverter.convertToToken(
            refreshToken.identity,
            refreshToken.clientId,
            refreshToken.scopes,
            refreshTokenConverter.convertToToken(refreshToken)
        )

        tokenService.saveAccessToken(accessToken)
        return accessToken
    }

    fun refreshTokenGrantCall(
        callContextIn: CallContextIn,
        clientService: ClientService,
        identityService: IdentityService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): CallContextOut<AccessToken> {
        val validResult = refreshTokenRequestValidation.validate(callContextIn)
        if (validResult.errors.isNotEmpty()) {
            // FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val refreshTokenRequest = RefreshTokenRequest(
            path = callContextIn.path,
            method = callContextIn.method,
            clientId = callContextIn.formParameters["client_id"]!!,
            clientSecret = callContextIn.formParameters["client_secret"]!!,
            responseType = OAuth2ResponseType.valueOf(callContextIn.formParameters["response_type"]!!),
            refreshToken = callContextIn.formParameters["refresh_token"]!!,
            redirectUri = callContextIn.formParameters["redirect_uri"]!!,
            scope = callContextIn.formParameters["scope"]!!,
            state = callContextIn.formParameters["state"]!!,
        )
        val accessToken = refreshTokenRequestProcess(
            refreshTokenRequest = refreshTokenRequest,
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
