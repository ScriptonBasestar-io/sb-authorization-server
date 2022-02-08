package org.scriptonbasestar.auth.oauth2.scope

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.scriptonbasestar.auth.oauth2.grant_types.ScopeParser

internal class ScopeParserTest {
    @Test
    fun nullShouldResultInEmptySet() {
        Assertions.assertEquals(
            setOf<String>(),
            ScopeParser.parseScopes(null),
        )
    }

    @Test
    fun emptyStringShouldResultInEmptySet() {
        Assertions.assertEquals(
            setOf<String>(),
            ScopeParser.parseScopes(""),
        )
    }

    @Test
    fun setShouldBeSeparatedBySpace() {
        Assertions.assertEquals(
            setOf("foo", "bar"),
            ScopeParser.parseScopes("foo bar"),
        )
    }
}
