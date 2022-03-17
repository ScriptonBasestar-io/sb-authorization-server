package org.scriptonbasestar.auth.oauth2.grant_types.refresh

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext
import org.scriptonbasestar.auth.oauth2.endpoints.Endpoint
import org.scriptonbasestar.auth.oauth2.endpoints.EndpointConstants

class RefreshEndpoint(
    override val method: Set<HttpMethod> = setOf(HttpMethod.POST),
    override val protocol: String = "https",
    override val rootUrl: String,
    override val path: String = EndpointConstants.TOKEN_PATH,
) : Endpoint {
    override fun isMatch(requestPath: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun process(callContext: CallContext, cb: () -> Unit) {
        TODO("Not yet implemented")
    }
}
