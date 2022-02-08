package org.scriptonbasestar.auth.oauth2.endpoints

import org.scriptonbasestar.auth.oauth2.model.Credentials

interface RedirectRouter {
    fun route(callContext: CallContext, credentials: Credentials?): RedirectRouterResponse
}
