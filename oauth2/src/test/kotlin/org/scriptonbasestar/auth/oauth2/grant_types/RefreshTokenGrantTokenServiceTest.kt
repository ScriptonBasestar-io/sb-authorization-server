package org.scriptonbasestar.auth.oauth2.grant_types

import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidIdentityException
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import java.time.Instant

@ExtendWith(MockKExtension::class)
internal class RefreshTokenGrantTokenServiceTest {
    @MockK
    lateinit var callContext: CallContextIn

    @MockK
    lateinit var identityService: IdentityService

    @MockK
    lateinit var clientService: ClientService

    @RelaxedMockK
    lateinit var tokenStore: TokenService

    @MockK
    lateinit var accessTokenConverter: AccessTokenConverter

    @MockK
    lateinit var refreshTokenConverter: RefreshTokenConverter

    @MockK
    lateinit var codeTokenConverter: CodeTokenConverter

    val clientId = "client-foo"
    val clientSecret = "client-bar"
    val refreshToken = "refresh-token"
    val username = "foo-user"
    val scope = "scope1"
    val scopes = setOf(scope)
    val identity = Identity(username)

    @BeforeEach
    fun beforeEach() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.REFRESH_TOKEN))
        val token = RefreshToken("test", Instant.now(), identity, clientId, scopes)
        val newRefreshToken = RefreshToken("new-test", Instant.now(), identity, clientId, scopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, scopes, newRefreshToken)
        val identity = Identity(username)

        every { clientService.findByClientId(clientId).orElseThrow { InvalidClientException("client not found") } } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { tokenStore.refreshToken(refreshToken) } returns token
        every { identityService.identityOf(client, username).orElseThrow { InvalidIdentityException("identity not found") } } returns identity
        every { refreshTokenConverter.convertToToken(token) } returns newRefreshToken
        every { accessTokenConverter.convertToToken(identity, clientId, scopes, newRefreshToken) } returns accessToken
    }

    @Test
    fun validRefreshToken() {
        println("dddd")
//        callRouterRefresh.refresh(refreshTokenRequest)
//        verify { tokenStore.saveAccessToken(accessToken) }
    }

//    @Test
//    fun missingRefreshToken() {
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.REFRESH_TOKEN))
//
//        every { clientService.clientOf(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//
//        val refreshTokenRequest = RefreshTokenRequest(
//            clientId,
//            clientSecret,
//            null
//        )
//
//        Assertions.assertThrows(
//            InvalidRequestException::class.java
//        ) { callRouterRefresh.refresh(refreshTokenRequest) }
//    }

//    @Test
//    fun nonExistingClientException() {
//        every { clientService.findByClientId(clientId) } returns null
//
//        Assertions.assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterRefresh.refresh(refreshTokenRequest) }
//    }
//
//    @Test
//    fun invalidClientException() {
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.REFRESH_TOKEN))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns false
//
//        Assertions.assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterRefresh.refresh(refreshTokenRequest) }
//    }
//
//    @Test
//    fun storedClientDoesNotMatchRequestedException() {
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.REFRESH_TOKEN))
//        val token = RefreshToken("test", Instant.now(), identity, "wrong-client", scopes)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { tokenStore.refreshToken(refreshToken) } returns token
//
//        Assertions.assertThrows(
//            InvalidGrantException::class.java
//        ) { callRouterRefresh.refresh(refreshTokenRequest) }
//    }
}
