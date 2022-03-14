package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.endpoints.Endpoint
import org.scriptonbasestar.auth.oauth2.grant_types.AuthorizationCodeDefinition

class AuthorizationCodeEndpoint(
    override val url: String,
    override val protocol: String,
    override val host: String,
    override val path: String,
    val definition: AuthorizationCodeDefinition.ServerAuthorizeRequest,
) : Endpoint {
    override fun isMatch(requestPath: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun process(callContext: CallContext, cb: () -> Unit) {
        TODO("Not yet implemented")
    }
}
