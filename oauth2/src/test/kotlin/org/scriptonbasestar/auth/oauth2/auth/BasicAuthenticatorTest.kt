package org.scriptonbasestar.auth.oauth2.auth

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.oauth2.endpoints.BasicAuthenticator
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import java.util.*

internal class BasicAuthenticatorTest {

    @Test
    fun `test authorization head is case insensitive with all uppercase input`() {
        `test authorization head is case insensitive with input`(
            "AUTHORIZATION"
        )
    }

    @Test
    fun `test authorization head is case insensitive with all lowercase input`() {
        `test authorization head is case insensitive with input`(
            "authorization"
        )
    }

    private fun `test authorization head is case insensitive with input`(authorizationKeyName: String) {
        val callContext = mockk<CallContext>()
        val username = "test"
        val password = "test-password"

        val testCredentials = Base64.getEncoder().encodeToString("$username:$password".toByteArray())

        every { callContext.headers } returns Headers(mapOf(authorizationKeyName to "basic $testCredentials"))
        val credentials = BasicAuthenticator(callContext)
            .extractCredentials()

        Assertions.assertNotNull(credentials)
        Assertions.assertEquals(username, credentials.username)
        Assertions.assertEquals(password, credentials.password)
    }
}
