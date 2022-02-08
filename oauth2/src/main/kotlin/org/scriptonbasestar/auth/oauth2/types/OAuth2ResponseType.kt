package org.scriptonbasestar.auth.oauth2.types

enum class OAuth2ResponseType(val value: String) {
    // authorization code
    CODE("code"),
    // implicit
    TOKEN("token"),
}
