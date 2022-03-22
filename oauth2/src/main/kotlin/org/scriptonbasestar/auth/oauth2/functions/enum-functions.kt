package org.scriptonbasestar.auth.oauth2.functions

inline fun <reified T : kotlin.Enum<T>> safeValueOf(type: String): T {
    return java.lang.Enum.valueOf(T::class.java, type)
}
