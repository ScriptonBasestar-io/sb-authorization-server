package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params

interface CallContext {
    val path: String
    val method: HttpMethod
    val headers: Headers
    val queryParameters: Params
    val formParameters: Params

    fun respondStatus(statusCode: Int)
    fun respondHeader(name: String, value: String)
    fun respondJson(content: Any)
    fun redirect(uri: String)
}
