package org.scriptonbasestar.auth.oauth2.types

enum class OAuth2GrantType(val value: String) {
    AUTHORIZATION_CODE("authorization_code"),
//    PKCE,
    CLIENT_CREDENTIALS("client_credentials"),
//    DEVICE_CODE("device_code"),
    REFRESH_TOKEN("refresh_token"),

    IMPLICIT("implicit"),
    PASSWORD("password"),
//    const val IMPLICIT = "implicit"
//    const val REFRESH_TOKEN = "refresh_token"
//    const val PASSWORD = "password"
//    const val AUTHORIZATION_CODE = "authorization_code"
//    const val CLIENT_CREDENTIALS = "client_credentials"
}
