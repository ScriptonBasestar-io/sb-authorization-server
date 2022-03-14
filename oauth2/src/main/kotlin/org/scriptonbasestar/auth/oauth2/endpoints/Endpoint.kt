package org.scriptonbasestar.auth.oauth2.endpoints

interface Endpoint {
    val url: String
    val protocol: String
    val host: String
    val path: String

    fun isMatch(requestPath: String): Boolean
    fun process(callContext: CallContext, cb: () -> Unit)
}
