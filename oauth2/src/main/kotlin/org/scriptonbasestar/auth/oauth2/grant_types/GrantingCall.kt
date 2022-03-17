package org.scriptonbasestar.auth.oauth2.grant_types

import org.scriptonbasestar.auth.oauth2.context.CallContext
import org.scriptonbasestar.auth.oauth2.model.ClientService
import org.scriptonbasestar.auth.oauth2.model.IdentityService
import org.scriptonbasestar.auth.oauth2.model.token.AccessTokenResponder
import org.scriptonbasestar.auth.oauth2.model.token.TokenService
import org.scriptonbasestar.auth.oauth2.model.token.converter.Converters

interface GrantingCall {
    val callContext: CallContext
    val identityService: IdentityService
    val clientService: ClientService
    val tokenStore: TokenService
    val converters: Converters
    val accessTokenResponder: AccessTokenResponder
}
