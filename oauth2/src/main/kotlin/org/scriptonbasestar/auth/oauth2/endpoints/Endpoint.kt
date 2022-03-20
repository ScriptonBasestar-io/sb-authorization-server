package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod

sealed interface Endpoint {
    val method: Set<HttpMethod>
    val protocol: String
    val rootUrl: String
    val path: String
}
