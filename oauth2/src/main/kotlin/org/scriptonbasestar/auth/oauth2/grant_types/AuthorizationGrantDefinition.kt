package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.types.OAuth2ResponseType
import org.scriptonbasestar.validation.Validation
import org.scriptonbasestar.validation.constraint.*

object AuthorizationGrantDefinition {
    data class PasswordRequest(
        val path: String = EndpointConstants.AUTHORIZATION_PATH,
        val method: Set<HttpMethod> = setOf(HttpMethod.POST),

        val clientId: String,

        val responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        val redirectUri: String?,
        val scope: String?,
        val state: String?,
    )

    val passwordRequest = Validation<CallContextIn> {
        CallContextIn::path required {
            notBlank()
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""")
        }
        CallContextIn::method required {
            enum(HttpMethod.POST)
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContextIn::formParameters required {
//            hasKey("")
        }
        CallContextIn::queryParameters required {
            hasKey("client_id")
            hasKey("client_secret")
            hasKey("username")
            hasKey("password")
            hasKey("scope")
        }
    }

    val clientCredentialsRequest = Validation<CallContextIn> {
        CallContextIn::path required {
            notBlank()
            pattern("""https://[a-zA-Z0-9-.]+/oauth/authorize""")
        }
        CallContextIn::method required {
            enum(HttpMethod.POST)
        }
        CallContextIn::headers required {
//            hasKeyValue("Content-Type", """application/json?.+""".toRegex())
            hasKeyValue("Content-Type", "application/x-www-form-urlencoded")
        }
        CallContextIn::formParameters required {
//            hasKey("")
        }
        CallContextIn::queryParameters required {
            hasKey("client_id")
            hasKey("client_secret")
            hasKey("username")
            hasKey("password")
            hasKey("scope")
        }
    }
}
