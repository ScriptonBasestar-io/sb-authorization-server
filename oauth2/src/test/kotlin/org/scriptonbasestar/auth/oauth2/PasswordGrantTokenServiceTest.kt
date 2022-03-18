package org.scriptonbasestar.auth.oauth2

import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import io.mockk.verify
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidIdentityException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidScopeException
import org.scriptonbasestar.auth.oauth2.grant_types.CallRouterAuthorize
import org.scriptonbasestar.auth.oauth2.grant_types.password.PasswordGrantRequest
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.TokenResponseToken
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import java.time.Instant

@ExtendWith(MockKExtension::class)
internal class PasswordGrantTokenServiceTest {
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

    @MockK
    lateinit var accessTokenResponder: AccessTokenResponder

    lateinit var callRouterAuthorize: CallRouterAuthorize

    @BeforeEach
    fun before() {
        callRouterAuthorize = CallRouterAuthorize(
            clientService,
            identityService,
            Converters(
                accessTokenConverter, refreshTokenConverter, codeTokenConverter
            ),
            tokenStore
        )
    }

    val clientId = "client-foo"
    val clientSecret = "client-bar"
    val username = "user-foo"
    val password = "password-bar"
    val scope = "scope1"
    val scopes = setOf(scope)

    val passwordGrantRequest = PasswordGrantRequest(
        clientId,
        clientSecret,
        username,
        password,
        scope
    )

    @Test
    fun validPasswordGrant() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)
        val requestScopes = setOf("scope1")
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = TokenResponseToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, requestScopes) } returns scopes
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken

        callRouterAuthorize.authorize(passwordGrantRequest)

        verify { tokenStore.storeAccessToken(accessToken) }
    }

    @Test
    fun nonExistingClientException() {
        every { clientService.clientOf(clientId) } returns null

        assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidClientException() {
        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns false

        assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
    }

//    @Test
//    fun missingUsernameException() {
//        val passwordGrantRequest = PasswordGrantRequest(
//            clientId,
//            clientSecret,
//            null,
//            password,
//            scope
//        )
//
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        every { clientService.clientOf(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//
//        assertThrows(
//            InvalidRequestException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }

//    @Test
//    fun missingPasswordException() {
//        val passwordGrantRequest = PasswordGrantRequest(
//            clientId,
//            clientSecret,
//            username,
//            null,
//            scope
//        )
//
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        every { clientService.clientOf(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//
//        assertThrows(
//            InvalidRequestException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }

    @Test
    fun invalidIdentityException() {
        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns false

        assertThrows(
            InvalidIdentityException::class.java
        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidIdentityScopeException() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, scopes) } returns setOf()

        assertThrows(
            InvalidScopeException::class.java
        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidRequestClientScopeException() {
        val client = Client(clientId, setOf("scope3"), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, scopes) } returns scopes

        assertThrows(
            InvalidScopeException::class.java
        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
    }

    @Test
    fun clientScopesAsFallback() {
        val passwordGrantRequest = PasswordGrantRequest(
            clientId,
            clientSecret,
            username,
            password,
            null
        )

        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)
        val requestScopes = setOf("scope1", "scope2")
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = TokenResponseToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, requestScopes) } returns requestScopes
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken

        callRouterAuthorize.authorize(passwordGrantRequest)
    }
}
