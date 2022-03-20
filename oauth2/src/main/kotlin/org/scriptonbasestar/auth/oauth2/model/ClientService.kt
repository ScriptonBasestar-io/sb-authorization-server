package org.scriptonbasestar.auth.oauth2.model

import java.util.Optional

/**
 * persistence data
 */
interface ClientService {
    // 인증에 필수적이지 않아서 제외
//    fun findAll(realm: Realm): List<Client>
//    fun findOne(realm: Realm, uuid: UUID): Client
//    fun findOne(realm: Realm, clientId: String): Client

    fun isValid(realm: Realm, client: Client, clientSecret: String): Boolean

    fun findByClientId(clientId: String): Optional<Client>
    fun validClient(client: Client, clientSecret: String): Boolean
}
