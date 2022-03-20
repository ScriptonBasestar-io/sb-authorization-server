package org.scriptonbasestar.auth.oauth2.definition

import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params
import org.scriptonbasestar.auth.oauth2.CallContextImpl
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeGrantDefinition
import kotlin.test.Test

/**
 * ph1 auth request
 * ph2 redirect
 * ph3 token exchange
 */
@ExtendWith(MockKExtension::class)
class AuthorizeDefinitionTest {

    @Test
    fun desktopAuthorizeRequestTest_success_case() {
        val callContext = CallContextImpl(
            path = "https://example.com/oauth/authorize",
            method = HttpMethod.GET,
            headers = Headers(
                mapOf(
                    "Content-Type" to "application/json"
                )
            ),
            queryParameters = Params(
                mapOf(
                    "client_id" to "1234567",
                    "response_type" to "code",
                    "state" to "1234",
                    "redirect_uri" to "https://example.com/auth",
                    "scope" to "profile email photo"
                )
            ),
            formParameters = Params()
        )
        val result = AuthorizationCodeGrantDefinition.commonAuthorizeRequestValidation.validate(callContext)
        println(result)
        Assertions.assertTrue(result.errors.isEmpty())
    }

    @Test
    fun mobileAuthorizeRequestTest_success_case() {
        val callContext = CallContextImpl(
            path = "https://example.com/oauth/authorize",
            method = HttpMethod.GET,
            headers = Headers(
                mapOf(
                    "Content-Type" to "application/json"
                )
            ),
            queryParameters = Params(
                mapOf(
                    "client_id" to "1234567",
                    "response_type" to "code",
                    "state" to "1234",
                    "redirect_uri" to "https://example.com/auth",
                    "scope" to "profile email photo",
                    "code_challenge" to "",
                    "code_challenge_method" to "S256",
                )
            ),
            formParameters = Params()
        )
        val result = AuthorizationCodeGrantDefinition.commonAuthorizeRequestValidation.validate(callContext)
        println(result)
        Assertions.assertTrue(result.errors.isEmpty())
    }

    @Test
    fun accessTokenRequestTest_success_case() {
        val callContext = CallContextImpl(
            path = "https://example.com/oauth/token",
            method = HttpMethod.POST,
            headers = Headers(
                mapOf(
                    "Content-Type" to "application/x-www-form-urlencoded",
                )
            ),
            formParameters = Params(
                mapOf(
                    "client_id" to "1234567",
                    "client_secret" to "1234567",
                    "redirect_uri" to "https://example.com/redirect",
                    "code" to "1234567",
                    "code_verifier" to "1234567",
                    "grant_type" to "authorization_code"
                )
            ),
            queryParameters = Params(),
        )
        val result = AuthorizationCodeGrantDefinition.accessTokenRequestValidation.validate(callContext)
        println(result)
        Assertions.assertTrue(result.errors.isEmpty())
    }
}
