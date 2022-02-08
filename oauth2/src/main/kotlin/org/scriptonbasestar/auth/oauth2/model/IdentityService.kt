package org.scriptonbasestar.auth.oauth2.model

import java.util.*

interface IdentityService : Authenticator, IdentityScopeVerifier {
    /**
     * Find identity within a client and username
     * If not found return null
     */
    fun identityOf(forClient: Client, username: String): Identity?

    // 회원관리는 다른모듈에서
//    fun findAll(realm: Realm): List<Identity>
//    fun findOne(realm: Realm, uuid: UUID): Identity
//    fun findOne(realm: Realm, userId: String): Identity

    fun isValidCredential(realm: Realm, credential: Credentials): Boolean
}
