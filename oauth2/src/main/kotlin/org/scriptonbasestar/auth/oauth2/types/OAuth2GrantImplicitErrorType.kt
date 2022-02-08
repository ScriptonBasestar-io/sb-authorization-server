package org.scriptonbasestar.auth.oauth2.types

enum class OAuth2GrantImplicitErrorType(val errorCode: OAuth2RequestErrorType, val message: String) {
    /**
     * client_id, response_type, redirect_uri
     */
    MISSING_PARAM(OAuth2RequestErrorType.INVALID_REQUEST, "Required parameter is missing: {}"), // 여러개
    /**
     * client_id, response_type, redirect_uri
     */
    INVALID_PARAM(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid parameter value: {}"),
}
