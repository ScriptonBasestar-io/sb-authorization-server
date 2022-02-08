package org.scriptonbasestar.auth.oauth2.model.token

import org.scriptonbasestar.auth.oauth2.model.Identity
import java.time.Instant

data class CodeToken(
    val codeToken: String,
    override val expireTime: Instant,
    val identity: Identity,
    val clientId: String,
    val redirectUri: String,
    val scopes: Set<String>
) : ExpirableToken
