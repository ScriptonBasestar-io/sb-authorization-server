package org.scriptonbasestar.auth.oauth2.endpoints

object CallContextBasicAuthenticator {
    fun handleAuthentication(context: CallContext, router: RedirectRouter) = with(BasicAuthenticator(context)) {
        router.route(context, this.extractCredentials()).also { response ->
            if (!response.successfulLogin)
                openAuthenticationDialog()
        }
    }
}
