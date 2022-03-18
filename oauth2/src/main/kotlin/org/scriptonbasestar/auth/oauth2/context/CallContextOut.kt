package org.scriptonbasestar.auth.oauth2.context

import org.scriptonbasestar.auth.http.Headers
import org.scriptonbasestar.auth.oauth2.types.HttpResponseType

interface CallContextOut<R> {
    val statusValue: Int
    val statusName: String
    val headers: Headers
    val responseType: HttpResponseType
    val responseValue: R
}
