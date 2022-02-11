package org.scriptonbasestar.auth.oauth2.thrid

import io.konform.validation.Validation
import io.konform.validation.jsonschema.enum
import org.junit.jupiter.api.Assertions
import org.scriptonbasestar.auth.http.HttpMethod
import kotlin.test.Test

class ValidationCustomTest {

    data class WrapMap(
        val method: HttpMethod,
        val queryParameters: Map<String, String>
    )

    @Test
    fun mapTest() {
        val validateAuthorizeRequest = Validation<WrapMap> {
            WrapMap::method required {
                enum(HttpMethod.GET)
            }
            WrapMap::queryParameters required {
                addConstraint("client_id is essential") {
                    it.containsKey("client_id") && it["client_id"]!!.isNotEmpty()
                }
                exists("client_id")
                exactKeyValue("response_type", "code")
            }
        }
        val result = validateAuthorizeRequest.validate(
            WrapMap(method = HttpMethod.POST, mapOf(Pair("client_id", "")))
        )
        println(result)
        Assertions.assertTrue(result.errors.isNotEmpty())
        Assertions.assertTrue(result.errors[".method"]!!.isNotEmpty())
        Assertions.assertTrue(result.errors[".queryParameters"]!!.isNotEmpty())
//        result.errors[""]
    }
}
