package org.scriptonbasestar.auth.oauth2.model

import java.util.*

interface RealmService {
    fun findAll(): List<Realm>
    fun findOne(uuid: UUID): Optional<Realm>
}
