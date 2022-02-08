package org.scriptonbasestar.auth.oauth2.model

data class Identity(
    val username: String,
    val metadata: Map<String, Any> = mapOf()
)
