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
import org.scriptonbasestar.auth.oauth2.model.token.CodeToken
import org.scriptonbasestar.auth.oauth2.model.token.RedirectCodeResponse
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RedirectCodeConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.HttpResponseType
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import org.scriptonbasestar.auth.oauth2.utils.ScopeParser
import org.scriptonbasestar.validation.Validation
import org.scriptonbasestar.validation.constraint.*

object AuthorizationCodeGrantDefinition {

    val redirectRequestValidation = Validation<CallContextIn> {
        CallContextIn::path required {
            startsWith(EndpointConstants.AUTHORIZATION_PATH)
        }
//        CallContextIn::protocol required {
//            enum(HttpProto.HTTPS)
//        }
        CallContextIn::method required {
            enum(HttpMethod.GET)
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
        }
        CallContextIn::formParameters required {
//            hasKey("")
        }
        CallContextIn::queryParameters required {
            hasKeyValueNotBlank("client_id")
            hasKeyValueNotBlank("redirect_uri")
            hasKey("scope")
//            hasKey("nonce")
            hasKeyValueNotBlank("state")
            hasKeyValue("response_type", OAuth2ResponseType.CODE, caseInsensitive = true)
        }
    }

    data class RedirectRequest(
        val clientId: String,
        val redirectUri: String,
        val scope: String,
        val state: String,
        val responseType: OAuth2ResponseType,
    )

    fun redirectProcess(
        redirectRequest: RedirectRequest,
        clientService: ClientService,
        redirectCodeConverter: RedirectCodeConverter,
        tokenService: TokenService,
    ): RedirectCodeResponse {
        val authorizedGrantType = OAuth2GrantType.AUTHORIZATION_CODE

        val requestedClient = clientService.findByClientId(redirectRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }

        if (redirectRequest.redirectUri == null) {
            throw InvalidRequestException(ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format("redirect_uri"))
        }
        // FIXME contains, startswith 도 추가필요
        if (!requestedClient.redirectUris.contains(redirectRequest.redirectUri)) {
            throw InvalidRequestException("redirect_uri you requested is not registered")
        }

        val requestedScopes = if (redirectRequest.scope != null && redirectRequest.scope.isNotBlank()) {
            ScopeParser.parseScopes(redirectRequest.scope).toSet()
        } else {
            requestedClient.clientScopes
        }

        val code = redirectCodeConverter.convertToToken(requestedClient.clientId, requestedScopes, redirectRequest.redirectUri)

        tokenService.redirectCodeSave(code)
        return code
    }

    fun redirectGrantCall(
        callContextIn: CallContextIn,
        clientService: ClientService,
        redirectCodeConverter: RedirectCodeConverter,
        tokenService: TokenService,
    ): CallContextOut<String> {
        val validResult = redirectRequestValidation(callContextIn)
        if (validResult.errors.isNotEmpty()) {
            // FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val redirectRequest = RedirectRequest(
            clientId = callContextIn.queryParameters["client_id"]!!,
            responseType = OAuth2ResponseType.valueOf(callContextIn.queryParameters["response_type"]!!.uppercase()),
            redirectUri = callContextIn.queryParameters["redirect_uri"]!!,
            scope = callContextIn.queryParameters["scope"]!!,
            state = callContextIn.queryParameters["state"]!!,
        )
        val code = redirectProcess(
            redirectRequest = redirectRequest,
            clientService = clientService,
            redirectCodeConverter = redirectCodeConverter,
            tokenService = tokenService,
        )

        return object : CallContextOut<String> {
            // https://developer.mozilla.org/ko/docs/Web/HTTP/Redirections
            override val statusValue: Int = 302
            override val statusName: String = "302"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                    // TODO redirect header?
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.REDIRECT
            override val responseValue: String = "${code.redirectUri}&code=${code.code}&state=${code.state}"
        }
    }

    /**
     * client_id
     *
     * response_type=code
     * redirect_uri (optional)
     * scope (optional)
     * state (recommended)
     * PKCE??
     */
    data class CommonAuthorizeRequest(
        val clientId: String,
        val clientSecret: String,

        val username: String,
        val password: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val commonAuthorizeRequestValidation = Validation<CallContextIn> {
        CallContextIn::path required {
            startsWith(EndpointConstants.AUTHORIZATION_PATH)
        }
//        CallContextIn::protocol required {
//            enum(HttpProto.HTTPS)
//        }
        CallContextIn::method required {
            enum(HttpMethod.POST)
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContextIn::queryParameters required {
//            hasKey("")
        }
        CallContextIn::formParameters required {
            hasKeyValueNotBlank("client_id") ex InvalidRequestException(
                ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format(
                    "client_id"
                )
            )
            hasKeyValueNotBlank("client_secret")
            hasKeyValueNotBlank("username")
            hasKeyValueNotBlank("password")
            hasKeyValueNotBlank("redirect_uri")
            hasKey("scope")
            hasKey("state")
            hasKeyValue("response_type", OAuth2ResponseType.CODE.value)
        }
    }

    fun commonAuthorizeProcess(
        commonAuthorizeRequest: CommonAuthorizeRequest,
        clientService: ClientService,
        identityService: IdentityService,
        codeTokenConverter: CodeTokenConverter,
        tokenService: TokenService
    ): CodeToken {
        val authorizedGrantType = OAuth2GrantType.AUTHORIZATION_CODE

        val requestedClient = clientService.findByClientId(commonAuthorizeRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }
        if (!clientService.validClient(requestedClient, commonAuthorizeRequest.clientSecret)) {
            throw InvalidClientException("client data is invalid")
        }

        if (commonAuthorizeRequest.redirectUri == null) {
            throw InvalidRequestException(ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format("redirect_uri"))
        }

        val requestedScopes = if (commonAuthorizeRequest.scope != null && commonAuthorizeRequest.scope.isNotBlank()) {
            ScopeParser.parseScopes(commonAuthorizeRequest.scope).toSet()
        } else {
            requestedClient.clientScopes
        }

        val requestedIdentity = identityService.identityOf(
            requestedClient, commonAuthorizeRequest.username
        ).orElseThrow {
            InvalidClientException("identity 있나?")
        }
        // TODO vaLID CREDENTIAL

//        GrantUtil.validateScopes(requestedClient, requestedIdentity, requestedScopes, identityService)

        val codeToken = codeTokenConverter.convertToToken(
            requestedIdentity,
            requestedClient.clientId,
            commonAuthorizeRequest.redirectUri,
            requestedScopes
        )

        tokenService.storeCodeToken(codeToken)

        return codeToken
    }

    fun commonGrantCall(
        callContextIn: CallContextIn,
        clientService: ClientService,
        identityService: IdentityService,
        codeTokenConverter: CodeTokenConverter,
        tokenService: TokenService,
    ): CallContextOut<CodeToken> {
        val validResult = commonAuthorizeRequestValidation(callContextIn)
        if (validResult.errors.isNotEmpty()) {
            // FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val commonAuthorizeRequest = CommonAuthorizeRequest(
            clientId = callContextIn.formParameters["client_id"]!!,
            clientSecret = callContextIn.formParameters["client_secret"]!!,
            username = callContextIn.formParameters["username"]!!,
            password = callContextIn.formParameters["password"]!!,
            responseType = OAuth2ResponseType.valueOf(callContextIn.formParameters["response_type"]!!.uppercase()),
            redirectUri = callContextIn.formParameters["redirect_uri"]!!,
            scope = callContextIn.formParameters["scope"]!!,
            state = callContextIn.formParameters["state"]!!,
        )
        val codeToken = commonAuthorizeProcess(
            commonAuthorizeRequest = commonAuthorizeRequest,
            clientService = clientService,
            identityService = identityService,
            codeTokenConverter = codeTokenConverter,
            tokenService = tokenService,
        )

        return object : CallContextOut<CodeToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: CodeToken = codeToken
        }
    }

    /**
     * client_id
     *
     * response_type=code
     * redirect_uri (possibly required)
     * state (required)
     * scope (optional)
     * code_challenge=
     * code_challenge_method=S256
     */
    data class MobileAuthorizeRequest(
        val path: String = EndpointConstants.TOKEN_PATH,
        val method: Set<HttpMethod> = setOf(HttpMethod.GET),

        val clientId: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String,

        val codeChallenge: String,
        val codeChallengeMethod: String,
    )

    val mobileAuthorizeRequest = Validation<CallContextIn> {
        CallContextIn::path required {
            startsWith(EndpointConstants.TOKEN_PATH)
        }
        CallContextIn::method required {
            enum(HttpMethod.GET)
        }
//        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
//        }
        CallContextIn::formParameters required {
        }
        CallContextIn::queryParameters required {
            hasKey("client_id")
            hasKeyValue("response_type", "code")
            hasKey("redirect_uri")
            hasKey("state")
            hasKey("scope")
            hasKeyValueNotBlank("code_challenge")
            hasKeyValueNotBlank("code_challenge_method")
        }
    }

    /**
     * Server, SinglePage
     *
     * client_id
     *
     * code (required)
     * redirect_uri (possibly required)
     * grant_type (required)
     *
     * code_verifier (required) mobileonly
     */
    data class AccessTokenRequest(
        val path: String = EndpointConstants.TOKEN_PATH,
        val method: HttpMethod = HttpMethod.POST,

        val clientId: String,
        val clientSecret: String?,

        val redirectUri: String?,
        val code: String,

        // mobile only
        val codeVerifier: String?,

        val grantType: OAuth2GrantType = OAuth2GrantType.AUTHORIZATION_CODE,
    )

    val accessTokenRequestValidation = Validation<CallContextIn> {
        CallContextIn::path required {
            startsWith(EndpointConstants.TOKEN_PATH)
        }
        CallContextIn::method required {
            enum(HttpMethod.POST)
        }
        CallContextIn::headers required {
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContextIn::formParameters required {
            hasKeyValueNotBlank("client_id")
            hasKey("client_secret")
            hasKey("redirect_uri")
            hasKeyValueNotBlank("code")
            hasKey("code_verifier")
            hasKeyValue("grant_type", "authorization_code")
        }
        CallContextIn::queryParameters required {
            maxItems(1)
        }
    }

    fun tokenAuthorizeProcess(
        accessTokenRequest: AccessTokenRequest,
        clientService: ClientService,
        identityService: IdentityService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService
    ): AccessToken {
        val authorizedGrantType = OAuth2GrantType.AUTHORIZATION_CODE

        val requestedClient = clientService.findByClientId(accessTokenRequest.clientId).orElseThrow {
            InvalidClientException("client for clientId you provided is null")
        }
//        if (!clientService.validClient(requestedClient, accessTokenRequest.clientSecret)) {
//            throw InvalidClientException("client data is invalid")
//        }
        if (accessTokenRequest.code == null) {
            throw InvalidRequestException(ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format("code"))
        }

        if (accessTokenRequest.redirectUri == null) {
            throw InvalidRequestException(ErrorMessage.INVALID_REQUEST_FIELD_MESSAGE.format("redirect_uri"))
        }

        val consumeCodeToken = tokenService.consumeCodeToken(accessTokenRequest.code)
            ?: throw InvalidGrantException("token for ${accessTokenRequest.code} must not null")

        if (consumeCodeToken.redirectUri != accessTokenRequest.redirectUri || consumeCodeToken.clientId != accessTokenRequest.clientId) {
            throw InvalidGrantException("invalid grant")
        }

        val accessToken = accessTokenConverter.convertToToken(
            consumeCodeToken.identity,
            consumeCodeToken.clientId,
            consumeCodeToken.scopes,
            refreshTokenConverter.convertToToken(
                consumeCodeToken.identity,
                consumeCodeToken.clientId,
                consumeCodeToken.scopes
            )
        )

        tokenService.saveAccessToken(accessToken)

        return accessToken
    }

    fun authorizationGrantCall(
        callContextIn: CallContextIn,
        clientService: ClientService,
        identityService: IdentityService,
        accessTokenConverter: AccessTokenConverter,
        refreshTokenConverter: RefreshTokenConverter,
        tokenService: TokenService,
    ): CallContextOut<AccessToken> {
        val validResult = accessTokenRequestValidation(callContextIn)
        if (validResult.errors.isNotEmpty()) {
            // FIXME 메시지 출력 json
            throw InvalidRequestException(validResult.errors.map { it.value }.joinToString(","))
        }
        // TODO valid 완료후 자동매핑
        val accessTokenRequest = AccessTokenRequest(
            path = callContextIn.path,
            method = callContextIn.method,
            clientId = callContextIn.formParameters["client_id"]!!,
            clientSecret = callContextIn.formParameters["client_secret"]!!,
            redirectUri = callContextIn.formParameters["redirect_uri"]!!,
            code = callContextIn.formParameters["code"]!!,
            codeVerifier = callContextIn.formParameters["code_verifier"]!!,
            grantType = OAuth2GrantType.valueOf(callContextIn.formParameters["grant_type"]!!),
        )
        val accessToken = tokenAuthorizeProcess(
            accessTokenRequest = accessTokenRequest,
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
