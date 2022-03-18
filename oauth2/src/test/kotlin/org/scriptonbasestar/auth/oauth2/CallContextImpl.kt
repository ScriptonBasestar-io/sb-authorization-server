package org.scriptonbasestar.auth.oauth2

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.context.CallContextOut

class CallContextImpl(
    override val path: String,
    override val method: HttpMethod,
    override val headers: Headers,
    override val queryParameters: Params,
    override val formParameters: Params
) : CallContextIn {
    override fun <R> out(cb: () -> Unit): CallContextOut<R> {
        TODO("Not yet implemented")
    }
}
