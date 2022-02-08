package org.scriptonbasestar.auth.oauth2.token

import org.apache.tools.ant.types.selectors.modifiedselector.Algorithm

class JwtTokenGenerator(
    private val algorithm: Algorithm
): TokenGenerator {
    override fun generate():TokenResponse{
    }
}
