package org.scriptonbasestar.auth.core.types

enum class OAuth2GrantAccessTokenErrorType(val errorCode: OAuth2RequestErrorType, val message: String) {
    /**
     * code(authorization_code), redirect_uri, client_id, grant_type
     * username, password
     */
    MISSING_PARAMETER(OAuth2RequestErrorType.INVALID_REQUEST, "Required parameter is missing: {}"), // 여러개

    /**
     * code(authorization_code), redirect_uri, client_id, grant_type
     * username, password
     */
//    INVALID_PARAM(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid parameter value: {}"),
    INVALID_AUTHORIZATION_CODE(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid authorization_code"),
    INVALID_REDIRECT_URI(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid 'redirect_uri': oob"),
    INVALID_CLIENT_ID(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid 'client_id': {}"),
    INVALID_GRANT_TYPE(OAuth2RequestErrorType.INVALID_REQUEST, "Unsupported 'grant_type': client_credentials_invalid"),
}
