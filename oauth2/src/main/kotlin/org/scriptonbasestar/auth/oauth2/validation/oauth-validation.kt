package org.scriptonbasestar.auth.oauth2.validation

import org.scriptonbasestar.auth.http.CaseInsensitiveOAuthValueMap
import org.scriptonbasestar.validation.Constraint
import org.scriptonbasestar.validation.builder.ValidationBuilderBase
import org.scriptonbasestar.validation.util.format

inline fun ValidationBuilderBase<out CaseInsensitiveOAuthValueMap>.hasKey(
    key: String,
): Constraint<out CaseInsensitiveOAuthValueMap> =
    addConstraint(
        "must hasKeys {0}".format(key.toString()),
    ) {
        it.containsKey(key)
    }

inline fun ValidationBuilderBase<out CaseInsensitiveOAuthValueMap>.hasKeyValue(
    key: String,
    value: String,
): Constraint<out CaseInsensitiveOAuthValueMap> =
    addConstraint(
        "must hasKey {0} and value equals with {1}".format(key.toString(), value.toString()),
    ) {
        it[key] == value
    }

inline fun ValidationBuilderBase<out CaseInsensitiveOAuthValueMap>.hasKeyValue(
    key: String,
    regex: Regex,
): Constraint<out CaseInsensitiveOAuthValueMap> =
    addConstraint(
        "must hasKey {0} and value equals with {1}".format(key.toString(), regex.toString()),
    ) {
        it[key] != null && it[key]!!.matches(regex)
    }

inline fun ValidationBuilderBase<out CaseInsensitiveOAuthValueMap>.hasKeyValueNotBlank(
    key: String,
): Constraint<out CaseInsensitiveOAuthValueMap> =
    addConstraint(
        "must hasKey {0} and value not blank".format(key.toString()),
    ) {
        it[key] != null && it[key]!!.length > 1
    }
