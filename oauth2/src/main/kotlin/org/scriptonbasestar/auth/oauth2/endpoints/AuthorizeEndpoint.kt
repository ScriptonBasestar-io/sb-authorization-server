package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.oauth2.grant_types.authorization_code.AuthorizationCodeEndpoint
import org.scriptonbasestar.auth.oauth2.model.Realm

class AuthorizeEndpoint {
    fun available(callContext: CallContext) {
    }
    fun authorization(realm: Realm, request: AuthorizationCodeEndpoint) {
    }
}
