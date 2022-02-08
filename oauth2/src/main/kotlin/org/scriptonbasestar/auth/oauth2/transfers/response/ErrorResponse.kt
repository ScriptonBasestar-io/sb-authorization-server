package org.scriptonbasestar.auth.oauth2.transfers.response

data class ErrorResponse(
    val code: String,
    val detail: String,
)
