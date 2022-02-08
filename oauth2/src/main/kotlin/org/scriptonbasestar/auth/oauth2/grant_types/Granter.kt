package org.scriptonbasestar.auth.oauth2.grant_types

class Granter(
    val grantType: String,
    val callback: () -> Unit
)
