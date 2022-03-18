package org.scriptonbasestar.auth.oauth2

import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidGrantException
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidRequestException
import org.scriptonbasestar.auth.oauth2.grant_types.CallRouterAuthorize
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeGrantRequest
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.*
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import java.time.Instant

@ExtendWith(MockKExtension::class)
internal class AuthorizationCodeGrantTokenServiceTest {
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
    val code = "user-foo"
    val redirectUri = "http://foo.lcoalhost"
    val username = "user-foo"
    val identity = Identity(username)

    val authorizationCodeRequest = AuthorizationCodeGrantRequest(
        clientId,
        clientSecret,
        code,
        redirectUri
    )

    @Test
    fun validAuthorizationCodeGrant() {
        val requestScopes = setOf("scope1")

        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        val identity = Identity(username)
        val codeToken = CodeToken(code, Instant.now(), identity, clientId, redirectUri, requestScopes)

        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = TokenResponseToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns identity
        every { tokenStore.consumeCodeToken(code) } returns codeToken
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken

        callRouterAuthorize.authorize(authorizationCodeRequest)
    }

    @Test
    fun nonExistingClientException() {
        every { clientService.clientOf(clientId) } returns null

        assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }

    @Test
    fun invalidClientException() {
        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns false

        assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }

    @Test
    fun missingCodeException() {
        val authorizationCodeRequest = AuthorizationCodeGrantRequest(
            clientId,
            clientSecret,
            null,
            redirectUri
        )

        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true

        assertThrows(
            InvalidRequestException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }

    @Test
    fun missingRedirectUriException() {
        val authorizationCodeRequest = AuthorizationCodeGrantRequest(
            clientId,
            clientSecret,
            code,
            null
        )

        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true

        assertThrows(
            InvalidRequestException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }

    @Test
    fun invalidRedirectUriException() {
        val wrongRedirectUri = ""
        val requestScopes = setOf("scope1")

        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        val codeToken = CodeToken(code, Instant.now(), identity, clientId, wrongRedirectUri, requestScopes)

        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = TokenResponseToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { tokenStore.consumeCodeToken(code) } returns codeToken
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken

        assertThrows(
            InvalidGrantException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }

    @Test
    fun invalidCodeException() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))

        every { clientService.clientOf(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { tokenStore.consumeCodeToken(code) } returns null

        assertThrows(
            InvalidGrantException::class.java
        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
    }
}
