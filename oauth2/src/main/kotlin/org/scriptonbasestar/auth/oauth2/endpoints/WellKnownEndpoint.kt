package org.scriptonbasestar.auth.oauth2.endpoints

class WellKnownEndpoint(
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
