package org.scriptonbasestar.auth.oauth2.grant_types

fun granter(grantType: String, callback: () -> Unit) = Granter(grantType, callback)
