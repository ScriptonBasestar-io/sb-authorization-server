package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.endpoints.EndpointConstants
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import org.scriptonbasestar.validation.Validation
import org.scriptonbasestar.validation.constraint.*

object AuthorizationCodeDefinition {

    val INVALID_REQUEST_FIELD_MESSAGE = "'%s' field is missing"

    /**
     * client_id
     *
     * response_type=code
     * redirect_uri (optional)
     * scope (optional)
     * state (recommended)
     * PKCE??
     */
    data class CommonAuthorizeRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: Set<HttpMethod> = setOf(HttpMethod.GET),

        val clientId: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val commonAuthorizeRequest = Validation<CallContext> {
        CallContext::path required {
            notBlank()
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""")
        }
        CallContext::method required {
            enum(HttpMethod.GET)
        }
        CallContext::headers required {
            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
        }
        CallContext::formParameters required {
//            hasKey("")
        }
        CallContext::queryParameters required {
            hasKey("client_id")
            hasKey("scope")
            hasKeyValue("response_type", "code")
        }
    }

    /**
     * client_id
     *
     * response_type=code
     * redirect_uri (possibly required)
     * state (required)
     * scope (optional)
     * code_challenge=
     * code_challenge_method=S256
     */
    data class MobileAuthorizeRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: Set<HttpMethod> = setOf(HttpMethod.GET),

        val clientId: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String,

        val codeChallenge: String,
        val codeChallengeMethod: String,
    )

    val mobileAuthorizeRequest = Validation<CallContext> {
        CallContext::path required {
            notBlank()
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""")
        }
        CallContext::method required {
            enum(HttpMethod.GET)
        }
        CallContext::headers required {
            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
        }
        CallContext::formParameters required {
        }
        CallContext::queryParameters required {
            hasKey("client_id")
            hasKeyValue("response_type", "code")
            hasKey("redirect_uri")
            hasKey("state")
            hasKey("scope")
            hasKeyValueNotBlank("code_challenge")
            hasKeyValueNotBlank("code_challenge_method")
        }
    }

    data class CodeResponse(
        val code: String,
        val state: String,
    )

    /**
     * Server, SinglePage
     *
     * client_id
     *
     * code (required)
     * redirect_uri (possibly required)
     * grant_type (required)
     *
     * code_verifier (required) mobileonly
     */
    data class AccessTokenRequest(
        val path: String = EndpointConstants.TOKEN_PATH,
        val method: Set<HttpMethod> = setOf(HttpMethod.POST),

        val clientId: String,
        val clientSecret: String?,

        val redirectUri: String?,
        val code: String,

        // mobile only
        val codeVerifier: String?,

        val grantType: OAuth2GrantType = OAuth2GrantType.AUTHORIZATION_CODE,
    )

    val accessTokenRequest = Validation<CallContext> {
        CallContext::path required {
            notBlank()
            pattern("""https://[a-zA-Z0-9-.]+/oauth/token""")
        }
        CallContext::method required {
            enum(HttpMethod.POST)
        }
        CallContext::headers required {
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContext::formParameters required {
            hasKeyValueNotBlank("client_id")
            hasKey("client_secret")
            hasKey("redirect_uri")
            hasKeyValueNotBlank("code")
            hasKey("code_verifier")
            hasKeyValue("grant_type", "authorization_code")
        }
        CallContext::queryParameters required {
            maxItems(1)
        }
    }
}
