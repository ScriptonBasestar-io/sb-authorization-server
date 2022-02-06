package org.scriptonbasestar.auth.core.types

enum class OAuth2GrantAuthorizationCodeErrorType(val errorCode: OAuth2RequestErrorType, val message: String) {
    /**
     * redirect_uri, client_id, response_type
     */
    MISSING_PARAMETER(OAuth2RequestErrorType.INVALID_REQUEST, "Required parameter is missing: {}"), // 여러개

    /**
     * redirect_uri, client_id, response_type
     */
    INVALID_PARAM(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid parameter value: {}"),
}
