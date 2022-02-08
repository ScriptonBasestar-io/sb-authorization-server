package org.scriptonbasestar.auth.oauth2.token

import java.time.Instant
import java.time.temporal.ChronoUnit

interface TokenExpirable {
    val expireTime: Instant
//    val forceExpired: Boolean

    fun expiresIn(): Int = Instant.now().until(expireTime, ChronoUnit.SECONDS).toInt()

    fun expired(): Boolean = expiresIn() <= 0
}
