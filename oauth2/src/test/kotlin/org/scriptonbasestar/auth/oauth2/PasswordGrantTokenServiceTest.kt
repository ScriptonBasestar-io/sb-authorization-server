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
import org.scriptonbasestar.auth.oauth2.types.AuthorizedGrantType
import org.scriptonbasestar.auth.oauth2.context.CallContext
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidIdentityException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidScopeException
import org.scriptonbasestar.auth.oauth2.grant_types.GrantingCall
import org.scriptonbasestar.auth.oauth2.grant_types.authorize
import org.scriptonbasestar.auth.oauth2.grant_types.password_credentials.PasswordGrantRequest
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
import org.scriptonbasestar.auth.oauth2.model.token.AccessTokenResponder
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import java.time.Instant

@ExtendWith(MockKExtension::class)
internal class PasswordGrantTokenServiceTest {
    @MockK
    lateinit var callContext: CallContext

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

    lateinit var grantingCall: GrantingCall

    @BeforeEach
    fun initialize() {
        grantingCall = object : GrantingCall {
            override val callContext = this@PasswordGrantTokenServiceTest.callContext
            override val identityService = this@PasswordGrantTokenServiceTest.identityService
            override val clientService = this@PasswordGrantTokenServiceTest.clientService
            override val tokenStore = this@PasswordGrantTokenServiceTest.tokenStore
            override val converters = Converters(
                this@PasswordGrantTokenServiceTest.accessTokenConverter,
                this@PasswordGrantTokenServiceTest.refreshTokenConverter,
                this@PasswordGrantTokenServiceTest.codeTokenConverter
            )
            override val accessTokenResponder = this@PasswordGrantTokenServiceTest.accessTokenResponder
        }
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
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        val identity = Identity(username)
        val requestScopes = setOf("scope1")
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

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

        grantingCall.authorize(passwordGrantRequest)

        verify { tokenStore.storeAccessToken(accessToken) }
    }

    @Test
    fun nonExistingClientException() {
        every { clientService.clientOf(clientId) } returns null

        assertThrows(
            InvalidClientException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidClientException() {
        val client = Client(clientId, setOf(), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns false

        assertThrows(
            InvalidClientException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun missingUsernameException() {
        val passwordGrantRequest = PasswordGrantRequest(
            clientId,
            clientSecret,
            null,
            password,
            scope
        )

        val client = Client(clientId, setOf(), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true

        assertThrows(
            InvalidRequestException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun missingPasswordException() {
        val passwordGrantRequest = PasswordGrantRequest(
            clientId,
            clientSecret,
            username,
            null,
            scope
        )

        val client = Client(clientId, setOf(), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true

        assertThrows(
            InvalidRequestException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidIdentityException() {
        val client = Client(clientId, setOf(), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns false

        assertThrows(
            InvalidIdentityException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidIdentityScopeException() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, scopes) } returns setOf()

        assertThrows(
            InvalidScopeException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
    }

    @Test
    fun invalidRequestClientScopeException() {
        val client = Client(clientId, setOf("scope3"), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        val identity = Identity(username)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, scopes) } returns scopes

        assertThrows(
            InvalidScopeException::class.java
        ) { grantingCall.authorize(passwordGrantRequest) }
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

        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(AuthorizedGrantType.PASSWORD))
        val identity = Identity(username)
        val requestScopes = setOf("scope1", "scope2")
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

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

        grantingCall.authorize(passwordGrantRequest)
    }
}
