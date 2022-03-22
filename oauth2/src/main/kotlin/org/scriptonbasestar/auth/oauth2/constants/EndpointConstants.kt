package org.scriptonbasestar.auth.oauth2.constants

object EndpointConstants {
    // oauth2
    const val AUTHORIZATION_PATH = "/oauth2/authorize"
    const val TOKEN_PATH = "/oauth2/token"
    const val REVOCATION_PATH = "/oauth2/revoke"
    const val TOKEN_INTROSPECTION_PATH = "/oauth2/introspect"
    const val WELL_KNOWN_PATH = "/.well_known"

    // jwk
    const val JWK_SET_PATH = "/oauth2/jwks"

    // oidc
    const val CLIENT_REGISTRATION_PATH = "/connect/register"
    const val USERINFO_PATH = "/userinfo"
}
