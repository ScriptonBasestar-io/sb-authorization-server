package org.scriptonbasestar.auth.oauth2.types

enum class OAuth2RequestErrorType(httpStatusCode: Int) {
//    INVALID_CLIENT_CREDENTIALS(),
//    INVALID_REQUEST(400),
//    INVALID_CLIENT,
//    INVALID_GRANT,
//    UNAUTHORIZED_CLIENT,
//    UNSUPPORTED_GRANT_TYPE,
//    INVALID_SCOPE,

//    BAD_REQUEST(400),
    INVALID_REQUEST(400),
    UNAUTHORIZED(401),
}
