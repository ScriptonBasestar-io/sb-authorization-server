package org.scriptonbasestar.auth.oauth2.grant_types

interface ClientRequest {
    val clientId: String?
    val clientSecret: String?
}
