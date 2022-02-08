package org.scriptonbasestar.auth.oauth2.endpoints

object EndpointConstants {
    // oauth2
    const val AUTHORIZATION_URI = "/oauth2/authorize"
    const val TOKEN_URI = "/oauth2/token"
    const val REVOCATION_URI = "/oauth2/revoke"
    const val TOKEN_INTROSPECTION_URI = "/oauth2/introspect"
    const val WELL_KNOWN_URI = "/.well_known"

    // jwk
    const val JWK_SET_URI = "/oauth2/jwks"

    // oidc
    const val CLIENT_REGISTRATION_URI = "/connect/register"
    const val USERINFO_URI = "/userinfo"
}
