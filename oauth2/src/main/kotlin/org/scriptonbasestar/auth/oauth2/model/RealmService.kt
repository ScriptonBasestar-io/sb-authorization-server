package org.scriptonbasestar.auth.oauth2.model

import java.util.*

interface RealmService {
    // TODO page
    fun findAll()
    fun findOne(uuid: UUID)
    fun findOne(name: String)
}
