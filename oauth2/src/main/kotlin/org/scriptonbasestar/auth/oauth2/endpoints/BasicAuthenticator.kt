package org.scriptonbasestar.auth.oauth2.endpoints

open class BasicAuthenticator(protected val context: CallContext) {
    fun extractCredentials() = BasicAuth.parseCredentials(
        context.headerCaseInsensitive("authorization") ?: ""
    )

    fun openAuthenticationDialog() {
        context.respondHeader("WWW-Authenticate", "Basic realm=\"${context.queryParameters["client_id"]}\"")
    }
}
