package org.scriptonbasestar.auth.oauth2.grant_types

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
import org.scriptonbasestar.auth.oauth2.CallContextInImpl
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
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
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import java.time.Instant
import java.util.*

@ExtendWith(MockKExtension::class)
internal class PasswordGrantTokenServiceTest {
    @MockK
    lateinit var callContext: CallContextIn

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

    val clientId = "client-foo"
    val clientSecret = "client-bar"
    val username = "user-foo"
    val password = "password-bar"
    val scope = "scope1"
    val state = "123465"

    @BeforeEach
    fun before() {
        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
        val identity = Identity(username)
        val requestScopes = setOf("scope1")
        val allowedScopes = setOf("default1", "scope1")
        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)

        every { clientService.findByClientId(clientId) } returns Optional.of(client)
        every { clientService.validClient(client, clientSecret) } returns true
        every { identityService.identityOf(client, username) } returns Optional.of(identity)
        every { identityService.validCredentials(client, identity, password) } returns true
        every { identityService.allowedScopes(client, identity, requestScopes) } returns allowedScopes
        every { refreshTokenConverter.convertToToken(identity, clientId, requestScopes) } returns refreshToken
        every {
            accessTokenConverter.convertToToken(
                identity,
                clientId,
                requestScopes,
                refreshToken
            )
        } returns accessToken
    }
    @Test
    fun passwordGrant_Token() {
        val callContextIn = CallContextInImpl(
            protocol = HttpProto.HTTP,
            path = EndpointConstants.AUTHORIZATION_PATH,
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
                    "scope" to scope,
                    "response_type" to OAuth2ResponseType.CODE.value,
                )
            ),
        )
        val result = PasswordGrantDefinition.passwordRequestValidation(callContextIn)
        println(result.errors)
        Assertions.assertTrue(result.errors.isEmpty())

        val contextOut = PasswordGrantDefinition.passwordGrantCall(
            callContextIn = callContextIn,
            clientService = clientService,
            identityService = identityService,
            accessTokenConverter = accessTokenConverter,
            refreshTokenConverter = refreshTokenConverter,
            tokenService = tokenService,
        )
        println(contextOut)
    }

//    @Test
//    fun validPasswordGrant() {
//
//        callRouterAuthorize.authorize(passwordGrantRequest)
//
//        verify { tokenService.saveAccessToken(accessToken) }
//    }
//
//    @Test
//    fun nonExistingClientException() {
//        every { clientService.findByClientId(clientId) } returns null
//
//        assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }
//
//    @Test
//    fun invalidClientException() {
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns false
//
//        assertThrows(
//            InvalidClientException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }
//
// //    @Test
// //    fun missingUsernameException() {
// //        val passwordGrantRequest = PasswordGrantRequest(
// //            clientId,
// //            clientSecret,
// //            null,
// //            password,
// //            scope
// //        )
// //
// //        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
// //        every { clientService.clientOf(clientId) } returns client
// //        every { clientService.validClient(client, clientSecret) } returns true
// //
// //        assertThrows(
// //            InvalidRequestException::class.java
// //        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
// //    }
//
// //    @Test
// //    fun missingPasswordException() {
// //        val passwordGrantRequest = PasswordGrantRequest(
// //            clientId,
// //            clientSecret,
// //            username,
// //            null,
// //            scope
// //        )
// //
// //        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
// //        every { clientService.clientOf(clientId) } returns client
// //        every { clientService.validClient(client, clientSecret) } returns true
// //
// //        assertThrows(
// //            InvalidRequestException::class.java
// //        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
// //    }
//
//    @Test
//    fun invalidIdentityException() {
//        val client = Client(clientId, setOf(), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        val identity = Identity(username)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { identityService.identityOf(client, username) } returns identity
//        every { identityService.validCredentials(client, identity, password) } returns false
//
//        assertThrows(
//            InvalidIdentityException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }
//
//    @Test
//    fun invalidIdentityScopeException() {
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        val identity = Identity(username)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { identityService.identityOf(client, username) } returns identity
//        every { identityService.validCredentials(client, identity, password) } returns true
//        every { identityService.allowedScopes(client, identity, scopes) } returns setOf()
//
//        assertThrows(
//            InvalidScopeException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }
//
//    @Test
//    fun invalidRequestClientScopeException() {
//        val client = Client(clientId, setOf("scope3"), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        val identity = Identity(username)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { identityService.identityOf(client, username) } returns identity
//        every { identityService.validCredentials(client, identity, password) } returns true
//        every { identityService.allowedScopes(client, identity, scopes) } returns scopes
//
//        assertThrows(
//            InvalidScopeException::class.java
//        ) { callRouterAuthorize.authorize(passwordGrantRequest) }
//    }
//
//    @Test
//    fun clientScopesAsFallback() {
//        val passwordGrantRequest = PasswordGrantRequest(
//            clientId,
//            clientSecret,
//            username,
//            password,
//            null
//        )
//
//        val client = Client(clientId, setOf("scope1", "scope2"), setOf(), setOf(OAuth2GrantType.PASSWORD))
//        val identity = Identity(username)
//        val requestScopes = setOf("scope1", "scope2")
//        val refreshToken = RefreshToken("test", Instant.now(), identity, clientId, requestScopes)
//        val accessToken = AccessToken("test", "bearer", Instant.now(), identity, clientId, requestScopes, refreshToken)
//
//        every { clientService.findByClientId(clientId) } returns client
//        every { clientService.validClient(client, clientSecret) } returns true
//        every { identityService.identityOf(client, username) } returns identity
//        every { identityService.validCredentials(client, identity, password) } returns true
//        every { identityService.allowedScopes(client, identity, requestScopes) } returns requestScopes
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
//        callRouterAuthorize.authorize(passwordGrantRequest)
//    }
}
