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

    @Test
    fun setShouldBeSeparatedByPlusCharacter() {
        Assertions.assertEquals(
            setOf("foo", "bar"),
            ScopeParser.parseScopes("foo+bar"),
        )
    }

    @Test
    fun `더하기랑 공백이랑 막 섞여있고 앞에 공백있는 개판 클라이언트도 통과시켜줘야 하는건가`() {
        Assertions.assertEquals(
            setOf("foo", "bar"),
            ScopeParser.parseScopes("foo + bar"),
        )
        Assertions.assertEquals(
            setOf("foo", "bar"),
            ScopeParser.parseScopes(" foo + bar"),
        )
    }
}
