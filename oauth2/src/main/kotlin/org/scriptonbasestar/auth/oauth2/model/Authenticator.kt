package org.scriptonbasestar.auth.oauth2.model

interface Authenticator {
    fun validCredentials(forClient: Client, identity: Identity, password: String): Boolean
}
