package org.scriptonbasestar.auth.oauth2.definition

import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params
import org.scriptonbasestar.auth.oauth2.CallContextImpl
import org.scriptonbasestar.auth.oauth2.grant_types.AuthorizationCodeDefinition
import org.testng.asserts.Assertion
import kotlin.test.Test

@ExtendWith(MockKExtension::class)
class AuthorizeDefinitionTest {

    @Test
    fun authorizeRequestTest() {
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
        val result = AuthorizationCodeDefinition.validateAuthorizeRequest.validate(callContext)
        println(result)
        Assertions.assertTrue(result.errors.isEmpty())
    }
}
