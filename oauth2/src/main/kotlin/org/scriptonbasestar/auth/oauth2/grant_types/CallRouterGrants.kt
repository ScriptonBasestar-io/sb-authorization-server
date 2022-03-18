package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.context.CallContextOut
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeGrantRequest
import org.scriptonbasestar.auth.oauth2.grant_types.password.PasswordGrantRequest
import org.scriptonbasestar.auth.oauth2.grant_types.refresh_token.RefreshTokenRequest
import org.scriptonbasestar.auth.oauth2.model.*
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.types.HttpResponseType

class CallRouterGrants(
    private val clientService: ClientService,
    private val identityService: IdentityService,
    private val converters: Converters,
    private val tokenService: TokenService,
    private val callRouterAuthorize: CallRouterAuthorize,
    private val callRouterRefresh: CallRouterRefresh,
) {
    fun grantPassword(callContextIn: CallContextIn): CallContextOut<TokenResponseToken> {
        val accessToken = callRouterAuthorize.authorize(
            PasswordGrantRequest(
                callContextIn.formParameters["client_id"],
                callContextIn.formParameters["client_secret"],
                callContextIn.formParameters["username"]!!,
                callContextIn.formParameters["password"]!!,
                callContextIn.formParameters["scope"]
            )
        )

        return object : CallContextOut<TokenResponseToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: TokenResponseToken = accessToken
        }
    }

    fun grantClientCredentials(callContextIn: CallContextIn): CallContextOut<TokenResponseToken> {
        val accessToken = callRouterAuthorize.authorize(
            ClientCredentialsRequest(
                callContextIn.formParameters["client_id"],
                callContextIn.formParameters["client_secret"],
                callContextIn.formParameters["scope"]
            )
        )

        return object : CallContextOut<TokenResponseToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: TokenResponseToken = accessToken
        }
    }

    fun grantRefreshToken(callContextIn: CallContextIn): CallContextOut<TokenResponseToken> {
        val accessToken = callRouterRefresh.refresh(
            RefreshTokenRequest(
                callContextIn.formParameters["client_id"],
                callContextIn.formParameters["client_secret"],
                callContextIn.formParameters["refresh_token"]!!
            )
        )

        return object : CallContextOut<TokenResponseToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: TokenResponseToken = accessToken
        }
    }

    fun grantAuthorizationCode(callContextIn: CallContextIn): CallContextOut<TokenResponseToken> {
        val accessToken = callRouterAuthorize.authorize(
            AuthorizationCodeGrantRequest(
                callContextIn.formParameters["client_id"],
                callContextIn.formParameters["client_secret"],
                callContextIn.formParameters["code"],
                callContextIn.formParameters["redirect_uri"]
            )
        )

        return object : CallContextOut<TokenResponseToken> {
            override val statusValue: Int = 200
            override val statusName: String = "200"
            override val headers: Headers = Headers(
                mapOf(
                    "Cache-Control" to "no-store",
                    "Pragma" to "no-cache",
                )
            )
            override val responseType: HttpResponseType = HttpResponseType.JSON
            override val responseValue: TokenResponseToken = accessToken
        }
    }

//    fun tokenInfo(accessToken: String): TokenInfo {
//        val storedAccessToken = tokenStore.accessToken(accessToken) ?: throw InvalidGrantException("token is not valid")
//        val client = clientService.clientOf(storedAccessToken.clientId)
//            ?: throw InvalidClientException("client for clientId you provided is null")
//        val identity = storedAccessToken.identity?.let { identityService.identityOf(client, it.username) }
//
//        return TokenInfo(
//            identity,
//            client,
//            storedAccessToken.scopes
//        )
//    }
}
