package org.scriptonbasestar.auth.oauth2

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params
import org.scriptonbasestar.auth.oauth2.endpoints.CallContext

class CallContextImpl(
    override val path: String,
    override val method: HttpMethod,
    override val headers: Headers,
    override val queryParameters: Params,
    override val formParameters: Params
) : CallContext {
    override fun respondStatus(statusCode: Int) {
        TODO("Not yet implemented")
    }

    override fun respondHeader(name: String, value: String) {
        TODO("Not yet implemented")
    }

    override fun respondJson(content: Any) {
        TODO("Not yet implemented")
    }

    override fun redirect(uri: String) {
        TODO("Not yet implemented")
    }
}
