package org.scriptonbasestar.auth.oauth2.model.token

/**
 * temporal data
 */
interface TokenService {
    fun saveAccessToken(accessToken: AccessToken)

    fun accessToken(token: String): AccessToken?

    fun revokeAccessToken(token: String)

    fun storeCodeToken(codeToken: CodeToken)

    fun codeToken(token: String): CodeToken?

    fun redirectCodeSave(redirectCode: RedirectCodeResponse)

    fun redirectCodeLoad(code: String): RedirectCodeResponse?
    /**
     * Retrieve token and delete it from store
     */
    fun consumeCodeToken(token: String): CodeToken?

    fun storeRefreshToken(refreshToken: RefreshToken)

    fun refreshToken(token: String): RefreshToken?

    fun revokeRefreshToken(token: String)
}
