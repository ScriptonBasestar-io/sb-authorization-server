package org.scriptonbasestar.auth.oauth2.grant_types

import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import kotlin.test.Test

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

    @Test
    fun test1() {
        println("test1")
    }

//    @BeforeEach
//    fun before() {
//        callRouterAuthorize = CallRouterAuthorize(
//            clientService,
//            identityService,
//            accessTokenConverter, refreshTokenConverter, codeTokenConverter,
//            tokenStore
//        )
//    }
//
//    private val clientId = "client-foo"
//    private val clientSecret = "client-secret"
//    private val scope = "scope1"
//    private val scopes = setOf(scope)
//    private val clientCredentialsRequest =
//        ClientCredentialsGrantDefinition.ClientCredentialsRequest(clientId, clientSecret, scope)
//
//    @Test
//    fun validClientCredentialsGrant() {
//        val client = Client(clientId, emptySet(), emptySet(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
//        val refreshToken = RefreshToken("test", Instant.now(), null, clientId, scopes)
//        val accessToken = AccessToken("test", "bearer", Instant.now(), null, clientId, scopes, refreshToken)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { refreshTokenConverter.convertToToken(null, clientId, scopes) } returns refreshToken
//        every { accessTokenConverter.convertToToken(null, clientId, scopes, refreshToken) } returns accessToken
//
//        callRouterAuthorize.authorize(clientCredentialsRequest)
//
//        verify { tokenStore.saveAccessToken(accessToken) }
//    }
//
//    @Test
//    fun nonExistingClientException() {
//        every { clientService.findByClientId(clientId) } returns null
//
//        Assertions.assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(clientCredentialsRequest) }
//    }
//
//    @Test
//    fun invalidClientException() {
//        val client = Client(clientId, emptySet(), emptySet(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns false
//
//        Assertions.assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(clientCredentialsRequest) }
//    }
//
//    @Test
//    fun clientScopesAsFallback() {
//        val clientCredentialsRequest = ClientCredentialsGrantDefinition.ClientCredentialsRequest(
//            clientId,
//            clientSecret,
//            null
//        )
//
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.CLIENT_CREDENTIALS))
//        val requestScopes = setOf("scope1", "scope2")
//        val refreshToken = RefreshToken("test", Instant.now(), null, clientId, requestScopes)
//        val accessToken = AccessToken("test", "bearer", Instant.now(), null, clientId, requestScopes, refreshToken)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { refreshTokenConverter.convertToToken(null, clientId, requestScopes) } returns refreshToken
//        every { accessTokenConverter.convertToToken(null, clientId, requestScopes, refreshToken) } returns accessToken
//
//        callRouterAuthorize.authorize(clientCredentialsRequest)
//    }
}
