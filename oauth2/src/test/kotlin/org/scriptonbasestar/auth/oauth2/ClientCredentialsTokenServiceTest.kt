package org.scriptonbasestar.auth.oauth2

import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import io.mockk.verify
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidClientException
import org.scriptonbasestar.auth.oauth2.grant_types.ClientCredentialsRequest
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessToken
import org.scriptonbasestar.auth.oauth2.model.token.RefreshToken
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import java.time.Instant

@ExtendWith(MockKExtension::class)
internal class ClientCredentialsTokenServiceTest {
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

    private val clientId = "client-foo"
    private val clientSecret = "client-secret"
    private val scope = "scope1"
    private val scopes = setOf(scope)
    private val clientCredentialsRequest = ClientCredentialsRequest(clientId, clientSecret, scope)

    @Test
    fun validClientCredentialsGrant() {
        val client = Client(clientId, emptySet(), emptySet(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
        val refreshToken = RefreshToken("test", Instant.now(), null, clientId, scopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), null, clientId, scopes, refreshToken)

        every { clientService.findByClientId(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { refreshTokenConverter.convertToToken(null, clientId, scopes) } returns refreshToken
        every { accessTokenConverter.convertToToken(null, clientId, scopes, refreshToken) } returns accessToken

        callRouterAuthorize.authorize(clientCredentialsRequest)

        verify { tokenStore.saveAccessToken(accessToken) }
    }

    @Test
    fun nonExistingClientException() {
        every { clientService.findByClientId(clientId) } returns null

        Assertions.assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(clientCredentialsRequest) }
    }

    @Test
    fun invalidClientException() {
        val client = Client(clientId, emptySet(), emptySet(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
        every { clientService.findByClientId(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns false

        Assertions.assertThrows(
            InvalidClientException::class.java
        ) { callRouterAuthorize.authorize(clientCredentialsRequest) }
    }

    @Test
    fun clientScopesAsFallback() {
        val clientCredentialsRequest = ClientCredentialsRequest(
            clientId,
            clientSecret,
            null
        )

        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
        val requestScopes = setOf("scope1", "scope2")
        val refreshToken = RefreshToken("test", Instant.now(), null, clientId, requestScopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), null, clientId, requestScopes, refreshToken)

        every { clientService.findByClientId(clientId) } returns client
        every { clientService.validClient(client, clientSecret) } returns true
        every { refreshTokenConverter.convertToToken(null, clientId, requestScopes) } returns refreshToken
        every { accessTokenConverter.convertToToken(null, clientId, requestScopes, refreshToken) } returns accessToken

        callRouterAuthorize.authorize(clientCredentialsRequest)
    }
}
