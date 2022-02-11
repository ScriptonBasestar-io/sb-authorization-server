package org.scriptonbasestar.auth.oauth2.grant_types

import io.konform.validation.Validation
import io.konform.validation.jsonschema.*
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.thrid.*
import org.scriptonbasestar.auth.oauth2.types.OAuth2GrantType
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType

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
    data class ServerAuthorizeRequest(
        val path: String = "/oauth/authorize",
        val method: Set<HttpMethod> = setOf(HttpMethod.GET),

        val clientId: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val validateAuthorizeRequest = Validation<CallContext> {
        CallContext::method required {
            enum(HttpMethod.GET)
        }
        CallContext::path required {
            pattern(Regex("https://[a-zA-Z0-9.]/oauth/authorize"))
        }
        CallContext::headers required {
            exactKeyValue("Content-Type", Regex("application/json*"))
        }
        CallContext::formParameters required {
            maxItems(1)
        }
        CallContext::queryParameters required {
            existsAndNotEmpty("client_id")
            exactKeyValue("response_type", "code")
            notEmpty("scope")
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
        val path: String = "/oauth/authorize",
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
        CallContext::method required {
            enum(HttpMethod.GET)
        }
        CallContext::path required {
            pattern(Regex("https://[a-zA-Z0-9.]/oauth/authorize"))
        }
        CallContext::headers required {
            exactKeyValue("Content-Type", Regex("application/json*"))
        }
        CallContext::formParameters required {
            maxItems(1)
        }
        CallContext::queryParameters required {
            existsAndNotEmpty("client_id")
            exactKeyValue("response_type", "code")
            existsAndNotEmpty("redirect_uri")
            existsAndNotEmpty("state")
            notEmpty("scope")
            existsAndNotEmpty("code_challenge")
            existsAndNotEmpty("code_challenge_method")
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
        val path: String = "/oauth/token",
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
        CallContext::method required {
            enum(HttpMethod.POST)
        }
        CallContext::path required {
            pattern(Regex("https://[a-zA-Z0-9.]/oauth/authorize"))
        }
        CallContext::headers required {
            exactKeyValue("Content-Type", Regex("application/x-www-form-urlencoded"))
        }
        CallContext::formParameters required {
            maxItems(1)
        }
        CallContext::queryParameters required {
            existsAndNotEmpty("client_id")
            notEmpty("client_secret")
            notEmpty("redirect_uri")
            existsAndNotEmpty("code")
            notEmpty("code_verifier")
            exists("grant_type")
        }
    }
}
