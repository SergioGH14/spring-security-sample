package es.sergomz.securitysample.config.jwt

import io.github.nefilim.kjwt.JWT
import io.github.nefilim.kjwt.sign
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service

@Service
class JWTService {

    companion object{
        const val TOKEN_PREFIX = "Bearer "
        const val HEADER = "Authorization"
        const val SECRET_KEY: String = ("TWO.BROTHERS.MEXICAN.ARMADA.TOMATO")
    }

    fun createToken(authentication: Authentication): String {
        val token = JWT.hs256 {
            claim("email", authentication.name)
        }
        token.sign(SECRET_KEY).fold({ throw SecurityException(it.toString()) }, { return it.rendered })
    }

    fun validate(token: String): Boolean {
        return token.isNotEmpty()
    }

    fun getUserName(header: String): String {
        val name = JWT.decode(header).fold({ throw SecurityException(it.toString()) }, { token ->
            token.claimValue("email")
        })
        name.fold({ throw SecurityException() }, { return it })
    }
}

