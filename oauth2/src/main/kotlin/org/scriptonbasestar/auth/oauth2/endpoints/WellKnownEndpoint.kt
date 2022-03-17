package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod

class WellKnownEndpoint(
    override val method: Set<HttpMethod> = setOf(HttpMethod.GET),
    override val protocol: String = "https",
    override val rootUrl: String,
    override val path: String = EndpointConstants.WELL_KNOWN_PATH,
) : Endpoint {
    override fun isMatch(requestPath: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun process(callContext: CallContext, cb: () -> Unit) {
        TODO("Not yet implemented")
    }
}
