package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod

class TokenEndpoint(
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
