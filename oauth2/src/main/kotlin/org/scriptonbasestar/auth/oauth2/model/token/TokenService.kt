package org.scriptonbasestar.auth.oauth2.model.token

interface TokenService {
    fun storeAccessToken(accessToken: AccessToken)

    fun accessToken(token: String): AccessToken?

    fun revokeAccessToken(token: String)

    fun storeCodeToken(codeToken: CodeToken)

    fun codeToken(token: String): CodeToken?

    /**
     * Retrieve token and delete it from store
     */
    fun consumeCodeToken(token: String): CodeToken?

    fun storeRefreshToken(refreshToken: RefreshToken)

    fun refreshToken(token: String): RefreshToken?

    fun revokeRefreshToken(token: String)
}
