package org.scriptonbasestar.auth.oauth2.types

enum class OAuth2GrantType {
    AUTHORIZATION_CODE,
    PKCE,
    CLIENT_CREDENTIALS,
    DEVICE_CODE,
    REFRESH_TOKEN,

    IMPLICIT,
    PASSWORD,
}
