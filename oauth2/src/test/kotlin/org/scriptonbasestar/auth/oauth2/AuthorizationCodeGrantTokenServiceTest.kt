package org.scriptonbasestar.auth.oauth2

import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.HttpProto
import org.scriptonbasestar.auth.http.Params
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeGrantDefinition
import org.scriptonbasestar.auth.oauth2.model.Client
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.Identity
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.*
import org.scriptonbasestar.auth.oauth2.model.token.converter.AccessTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.CodeTokenConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RedirectCodeConverter
import org.scriptonbasestar.auth.oauth2.model.token.converter.RefreshTokenConverter
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import java.time.Instant
import java.util.*

@ExtendWith(MockKExtension::class)
internal class AuthorizationCodeGrantTokenServiceTest {
    @MockK
    lateinit var identityService: IdentityService

    @MockK
    lateinit var clientService: ClientService

    @RelaxedMockK
    lateinit var tokenService: TokenService

    @MockK
    lateinit var accessTokenConverter: AccessTokenConverter

    @MockK
    lateinit var refreshTokenConverter: RefreshTokenConverter

    @MockK
    lateinit var codeTokenConverter: CodeTokenConverter

    @MockK
    lateinit var redirectCodeConverter: RedirectCodeConverter

    val clientId = "client-foo"
    val clientSecret = "client-bar"
    val code = "code-token"
    val redirectUri = "http://foo.lcoalhost"
    val username = "user-foo"
    val password = "passw0rd"
    val state = "1235"
    val scope = "scope1"
    val identity = Identity(username)

    @BeforeEach
    fun beforeEach() {
        val requestScopes = setOf("scope1")

        val client =
            Client(clientId, setOf("scope1", "scope2"), setOf(redirectUri), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
        val identity = Identity(username)

        val codeToken = CodeToken(code, Instant.now(), identity, clientId, redirectUri, requestScopes)
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        val redirectCode = RedirectCodeResponse(Instant.now(), code, state, redirectUri)

        every { clientService.findByClientId(clientId) } returns Optional.of(client)
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns Optional.of(identity)
        every { tokenService.consumeCodeToken(code) } returns codeToken
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every { codeTokenConverter.convertToToken(identity, clientId, redirectUri, requestScopes) } returns codeToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken
        every { redirectCodeConverter.convertToToken(clientId, requestScopes, redirectUri) } returns redirectCode
    }

    @Test
    fun validAuthorizationCodeGrant_Redirect() {
        val callContextIn = CallContextInImpl(
            protocol = HttpProto.HTTP,
            path = EndpointConstants.AUTHORIZATION_PATH,
            method = HttpMethod.GET,
            headers = Headers(),
            queryParameters = Params(
                mapOf(
                    "client_id" to clientId,
                    "redirect_uri" to redirectUri,
                    "state" to state,
                    "scope" to scope,
                    "response_type" to "code",
                )
            ),
            formParameters = Params(),
        )
        val result = AuthorizationCodeGrantDefinition.redirectRequestValidation(callContextIn)
        println(result.errors)
        Assertions.assertTrue(result.errors.isEmpty())

        val contextOut = AuthorizationCodeGrantDefinition.redirectGrantCall(
            callContextIn = callContextIn,
            clientService = clientService,
            redirectCodeConverter = redirectCodeConverter,
            tokenService = tokenService,
        )
        println(contextOut)
        // TODO validation
    }

    @Test
    fun validAuthorizationCodeGrant_Token() {
        val callContextIn = CallContextInImpl(
            protocol = HttpProto.HTTP,
            path = EndpointConstants.TOKEN_PATH,
            method = HttpMethod.POST,
            headers = Headers(
                mapOf(
                    "Content-Type" to "application/x-www-form-urlencoded"
                )
            ),
            queryParameters = Params(),
            formParameters = Params(
                mapOf(
                    "client_id" to clientId,
                    "client_secret" to clientSecret,
                    "username" to username,
                    "password" to password,
                    "redirect_uri" to redirectUri,
                    "state" to state,
                    "scope" to scope,
                    "response_type" to "code",
                )
            ),
        )
        val result = AuthorizationCodeGrantDefinition.commonAuthorizeRequestValidation(callContextIn)
        println(result.errors)
        Assertions.assertTrue(result.errors.isEmpty())

        val contextOut = AuthorizationCodeGrantDefinition.commonGrantCall(
            callContextIn = callContextIn,
            clientService = clientService,
            identityService = identityService,
            codeTokenConverter = codeTokenConverter,
            tokenService = tokenService,
        )
        println(contextOut)
    }

//    @Test
//    fun nonExistingClientException() {
//        every { clientService.findByClientId(clientId) } returns Optional.empty()
//
//        Assertions.assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }

//    @Test
//    fun invalidClientException() {
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns false
//
//        assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }
//
//    @Test
//    fun missingCodeException() {
//        val authorizationCodeRequest = AuthorizationCodeGrantRequest(
//            clientId,
//            clientSecret,
//            null,
//            redirectUri
//        )
//
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//
//        assertThrows(
//            InvalidRequestException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }
//
//    @Test
//    fun missingRedirectUriException() {
//        val authorizationCodeRequest = AuthorizationCodeGrantRequest(
//            clientId,
//            clientSecret,
//            code,
//            null
//        )
//
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//
//        assertThrows(
//            InvalidRequestException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }
//
//    @Test
//    fun invalidRedirectUriException() {
//        val wrongRedirectUri = ""
//        val requestScopes = setOf("scope1")
//
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
//        val codeToken = CodeToken(code, Instant.now(), identity, clientId, wrongRedirectUri, requestScopes)
//
//        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
//        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { tokenStore.consumeCodeToken(code) } returns codeToken
//        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
//        every {
//            accessTokenConverter.convertToToken(
//                identity,
//                clientId,
//                requestScopes,
//                refreshToken
//            )
//        } returns accessToken
//
//        assertThrows(
//            InvalidGrantException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }
//
//    @Test
//    fun invalidCodeException() {
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.AUTHORIZATION_CODE))
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { tokenStore.consumeCodeToken(code) } returns null
//
//        assertThrows(
//            InvalidGrantException::class.java
//        ) { callRouterAuthorize.authorize(authorizationCodeRequest) }
//    }
}
