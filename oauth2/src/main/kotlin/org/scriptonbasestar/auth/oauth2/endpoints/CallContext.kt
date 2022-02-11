package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod

interface CallContext {
    val path: String
    val method: HttpMethod
    val headers: Map<String, String>
    val queryParameters: Map<String, String>
    val formParameters: Map<String, String>

    fun respondStatus(statusCode: Int)
    fun respondHeader(name: String, value: String)
    fun respondJson(content: Any)
    fun redirect(uri: String)
}
