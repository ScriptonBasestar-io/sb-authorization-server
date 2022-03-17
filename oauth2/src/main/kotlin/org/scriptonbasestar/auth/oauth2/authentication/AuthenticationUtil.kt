package org.scriptonbasestar.auth.oauth2.authentication

import org.scriptonbasestar.auth.oauth2.model.Credentials
import java.util.*

object AuthenticationUtil {
    fun parseBasicAuthCredentials(authorization: String): Credentials {
        var username: String? = null
        var password: String? = null

        if (authorization.startsWith("basic ", true)) {
            val basicAuthorizationString = String(Base64.getDecoder().decode(authorization.substring(6)))

            with(basicAuthorizationString.split(":")) {
                if (this.size == 2) {
                    username = this[0]
                    password = this[1]
                }
            }
        }

        return Credentials(username, password)
    }
}
