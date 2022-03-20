package org.scriptonbasestar.auth.oauth2.model.token

import java.time.Instant

data class RedirectCodeResponse(
    override val expireTime: Instant,
    val code: String,
    val state: String,
    val redirectUri: String,
): ExpirableToken
