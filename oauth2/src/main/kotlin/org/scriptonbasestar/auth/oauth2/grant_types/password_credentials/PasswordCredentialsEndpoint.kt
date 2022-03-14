package org.scriptonbasestar.auth.oauth2.grant_types.password_credentials

import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.endpoints.Endpoint

class PasswordCredentialsEndpoint(
    override val url: String,
    override val protocol: String,
    override val host: String,
    override val path: String
) : Endpoint {
    override fun isMatch(requestPath: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun process(callContext: CallContext, cb: () -> Unit) {
        TODO("Not yet implemented")
    }
}
