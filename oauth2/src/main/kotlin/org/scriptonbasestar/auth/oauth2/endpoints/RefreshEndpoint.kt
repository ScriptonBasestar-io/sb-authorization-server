package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.endpoints.Endpoint
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants

class RefreshEndpoint(
    override val method: Set<HttpMethod> = setOf(HttpMethod.POST),
    override val protocol: String = "https",
    override val rootUrl: String,
    override val path: String = EndpointConstants.TOKEN_PATH,
) : Endpoint
