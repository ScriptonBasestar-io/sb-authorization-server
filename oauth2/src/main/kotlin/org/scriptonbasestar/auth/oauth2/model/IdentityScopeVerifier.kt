package org.scriptonbasestar.auth.oauth2.model

interface IdentityScopeVerifier {
    /**
     * Validate which scopes are allowed. Leave out the scopes which are not allowed
     */
    fun allowedScopes(forClient: Client, identity: Identity, scopes: Set<String>): Set<String>
}
