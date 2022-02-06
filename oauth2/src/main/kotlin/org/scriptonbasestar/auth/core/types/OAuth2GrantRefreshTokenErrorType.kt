package org.scriptonbasestar.auth.core.types

enum class OAuth2GrantRefreshTokenErrorType(val errorCode: OAuth2RequestErrorType, val message: String) {
    /**
     *
     */
    MISSING_PARAMETER(OAuth2RequestErrorType.INVALID_REQUEST, "Required parameter is missing: {}"), // 여러개

    INVALID_REFRESH_TOKEN(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid refresh_token"),
    TOKEN_EXPIRED_REFRESH(OAuth2RequestErrorType.INVALID_REQUEST, "Expired refresh_token"),
    INVALID_SCOPE(OAuth2RequestErrorType.INVALID_REQUEST, "Invalid refresh_token scope"),
}
