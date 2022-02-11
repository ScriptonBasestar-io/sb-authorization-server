package org.scriptonbasestar.auth.oauth2.thrid

import io.konform.validation.ValidationBuilder

fun ValidationBuilder<Map<String, String>>.exists(key: String) =
    addConstraint("{0} is essential", key) { it.containsKey(key) }

fun ValidationBuilder<Map<String, String>>.exactKeyValue(key: String, value: String) =
    addConstraint("{0} is essential and value must {1}", key, value) { it.containsKey(key) && it[key]!! == value }

fun ValidationBuilder<Map<String, String>>.exactKeyValue(key: String, regex: Regex) =
    addConstraint("{0} is essential and value must match {1}", key, regex.pattern) { it.containsKey(key) && regex.matches(it[key]!!) }

fun ValidationBuilder<Map<String, String>>.existsAndNotEmpty(key: String) =
    addConstraint("{0} is essential and value must empty", key) { it.containsKey(key) && it[key]!!.isNotEmpty() }

fun ValidationBuilder<Map<String, String>>.notEmpty(key: String) =
    addConstraint("{0} is essential and value must empty", key) { it[key]?.isNotEmpty() ?: false }
