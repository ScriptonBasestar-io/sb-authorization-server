package org.scriptonbasestar.auth.http

/**
 * oauth에서 key 겹치는거 없음
 */
abstract class CaseInsensitiveOAuthValueMap(
    map: Map<String, String>,
) : Map<String, String> {
    private val map: Map<String, String> = map.entries.associate {
        it.key.lowercase() to it.value
    }

    override operator fun get(key: String): String? =
        map[key.lowercase()]

    override val entries: Set<Map.Entry<String, String>>
        get() = map.entries

    override val keys: Set<String>
        get() = map.keys

    override val size: Int
        get() = map.size

    override val values: Collection<String>
        get() = map.values

    override fun containsKey(key: String): Boolean =
        map.containsKey(key.lowercase())

    override fun containsValue(value: String): Boolean =
        map.containsValue(value)

    override fun isEmpty(): Boolean =
        map.isEmpty()
}
