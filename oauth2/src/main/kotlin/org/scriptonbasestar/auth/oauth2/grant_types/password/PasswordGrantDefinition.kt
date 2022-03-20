package org.scriptonbasestar.auth.oauth2.grant_types.password

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.context.CallContextOut
import org.scriptonbasestar.auth.oauth2.exceptions.*
import org.scriptonbasestar.auth.oauth2.grant_types.GrantUtil
import org.scriptonbasestar.auth.oauth2.grant_types.ScopeParser
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.HttpResponseType
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import org.scriptonbasestar.validation.Validation
import org.scriptonbasestar.validation.constraint.*

/**
 * grantType = OAuth2GrantType.PASSWORD
 */
object PasswordGrantDefinition {
    data class PasswordRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: HttpMethod = HttpMethod.POST,

        val clientId: String,
        val clientSecret: String,

        val username: String,
        val password: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val passwordRequestValidation = Validation<CallContextIn> {
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
            hasKeyValueNotBlank("username") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "username"
                )
            )
            hasKeyValueNotBlank("password") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "password"
                )
            )
            hasKey("scope")
        }
    }

    /**
     * @throws InvalidIdentityException
     * @throws InvalidClientException
     * @throws InvalidScopeException
     */
    fun passwordRequestProcess(
        passwordRequest: PasswordRequest,
        clientService: ClientService,
        identityService: IdentityService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): AccessToken {
        val authorizedGrantType = OAuth2GrantType.PASSWORD

        val requestedClient = clientService.findByClientId(passwordRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }
        if (!clientService.validClient(requestedClient, passwordRequest.clientSecret)) {
            throw InvalidClientException("client data is invalid")
        }
        if (!requestedClient.authorizedGrantTypes.contains(authorizedGrantType)) {
            throw InvalidGrantException("Authorize not allowed: '$authorizedGrantType'")
        }
        val requestedIdentity = identityService.identityOf(requestedClient, passwordRequest.username).orElseThrow {
            InvalidGrantException("Identity for client is not found")
        }
        if (!identityService.validCredentials(requestedClient, requestedIdentity, passwordRequest.password)) {
            InvalidIdentityException("Identity for Client you provided is invalid")
        }
        val requestedScopes = if (passwordRequest.scope != null && passwordRequest.scope.isNotBlank()) {
            ScopeParser.parseScopes(passwordRequest.scope).toSet()
        } else {
            requestedClient.clientScopes
        }

        GrantUtil.validateScopes(requestedClient, requestedIdentity, requestedScopes, identityService)

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
            //FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val passwordRequest = PasswordGrantDefinition.PasswordRequest(
            path = callContextIn.path,
            method = callContextIn.method,
            clientId = callContextIn.formParameters["client_id"]!!,
            clientSecret = callContextIn.formParameters["client_secret"]!!,
            username = callContextIn.formParameters["username"]!!,
            password = callContextIn.formParameters["password"]!!,
            responseType = OAuth2ResponseType.valueOf(callContextIn.formParameters["response_type"]!!),
            redirectUri = callContextIn.formParameters["redirect_uri"]!!,
            scope = callContextIn.formParameters["scope"]!!,
            state = callContextIn.formParameters["state"]!!,
        )
        val accessToken = PasswordGrantDefinition.passwordRequestProcess(
            passwordRequest = passwordRequest,
            clientService = clientService,
            identityService = identityService,
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
