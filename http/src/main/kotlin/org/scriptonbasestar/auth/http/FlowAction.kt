package org.scriptonbasestar.auth.http

interface FlowAction {
    fun pre()
    fun action()
    fun post()
}
