package org.scriptonbasestar.auth.oauth2.context

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.http.Params

interface CallContextIn {
    val path: String
    val method: HttpMethod
    val headers: Headers
    val queryParameters: Params
    val formParameters: Params

    fun <R> out(cb: () -> Unit): CallContextOut<R>
}
