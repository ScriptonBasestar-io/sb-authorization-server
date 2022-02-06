package org.scriptonbasestar.auth.core.types

enum class OAuth2GrantType {
    AUTHORIZATION_CODE,
    PKCE,
    CLIENT_CREDENTIALS,
    DEVICE_CODE,
    REFRESH_TOKEN,

    IMPLICIT,
    PASSWORD,
}
