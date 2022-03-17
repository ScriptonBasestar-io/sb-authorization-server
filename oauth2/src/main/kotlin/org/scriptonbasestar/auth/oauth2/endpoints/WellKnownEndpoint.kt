package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.http.HttpMethod
import org.scriptonbasestar.auth.oauth2.constants.EndpointConstants

class WellKnownEndpoint(
    override val method: Set<HttpMethod> = setOf(HttpMethod.GET),
    override val protocol: String = "https",
    override val rootUrl: String,
    override val path: String = EndpointConstants.WELL_KNOWN_PATH,
) : Endpoint
