package org.scriptonbasestar.auth.oauth2.filter

import org.scriptonbasestar.auth.oauth2.context.CallContextIn

interface SBFilter {
    fun call(contextIn: CallContextIn)
}
