package org.scriptonbasestar.auth.oauth2.grant_types.authorization_code

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.endpoints.Endpoint
import org.scriptonbasestar.auth.oauth2.endpoints.EndpointConstants
import org.scriptonbasestar.auth.oauth2.grant_types.AuthorizationCodeDefinition

class AuthorizationCodeEndpoint(
    override val method: Set<HttpMethod> = setOf(HttpMethod.GET),
    override val protocol: String = "https",
    override val rootUrl: String,
    override val path: String = EndpointConstants.AUTHORIZATION_PATH,
    val definition: AuthorizationCodeDefinition.CommonAuthorizeRequest,
) : Endpoint {
    override fun isMatch(requestPath: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun process(callContext: CallContext, cb: () -> Unit) {
        TODO("Not yet implemented")
    }
}
