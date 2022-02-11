package org.scriptonbasestar.auth.http

class Parameters {
    private val params: Map<String, List<String>> by lazyOf(mapOf())

    fun get()
}
