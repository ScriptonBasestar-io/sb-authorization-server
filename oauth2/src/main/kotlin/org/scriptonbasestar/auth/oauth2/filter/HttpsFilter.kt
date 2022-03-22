package org.scriptonbasestar.auth.oauth2.filter

import org.scriptonbasestar.auth.http.HttpProto
import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.scriptonbasestar.auth.oauth2.exceptions.InvalidHttpProtoException

class HttpsFilter() : SBFilter {
    override fun call(contextIn: CallContextIn) {
        if (contextIn.protocol == HttpProto.HTTP) {
            throw InvalidHttpProtoException("https filter")
        }
    }
}
