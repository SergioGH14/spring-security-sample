package es.sergomz.securitysample.config.jwt

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import java.security.Principal

internal class JWTServiceTest {
    @Test
    fun `should create a json token`() {
        val token = jwtService.createToken(UsernamePasswordAuthenticationToken("name", "password"))
        assertTrue(token.isNotEmpty())
    }

    @Test
    fun `should return email of a token that exists`() {
        val token = jwtService.createToken(UsernamePasswordAuthenticationToken("name", "password"))
        assertTrue(jwtService.getUserName(token) == "name")
    }


    private val jwtService = JWTService()

}
