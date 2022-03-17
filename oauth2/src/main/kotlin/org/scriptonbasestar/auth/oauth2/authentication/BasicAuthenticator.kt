package org.scriptonbasestar.auth.oauth2.authentication

import org.scriptonbasestar.auth.http.HttpHeader
import org.scriptonbasestar.auth.oauth2.authentication.AuthenticationUtil
import org.scriptonbasestar.auth.oauth2.context.CallContext

open class BasicAuthenticator(protected val context: CallContext) {
    fun extractCredentials() = AuthenticationUtil.parseBasicAuthCredentials(
        context.headers[HttpHeader.AUTHORIZATION_KEY] ?: ""
    )

    fun openAuthenticationDialog() {
        context.respondHeader("WWW-Authenticate", "Basic realm=\"${context.queryParameters["client_id"]}\"")
    }
}
