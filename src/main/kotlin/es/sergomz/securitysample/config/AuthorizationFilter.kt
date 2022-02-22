package es.sergomz.securitysample.config

import es.sergomz.securitysample.config.jwt.JWTService
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class AuthorizationFilter(private val jwtService: JWTService, authenticationManager: AuthenticationManager) :
    BasicAuthenticationFilter(authenticationManager) {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val header = request.getHeader("Authorization")

        if (requiresAuthentication(header)) {
            val auth = if (jwtService.validate(header)) {
                val token = header.split(" ")[1]
                UsernamePasswordAuthenticationToken(jwtService.getUserName(token), null)
            } else {
                null
            }
            SecurityContextHolder.getContext().authentication = auth
            chain.doFilter(request, response)
        } else {
            chain.doFilter(request, response)
            return
        }
    }

    private fun requiresAuthentication(header: String?): Boolean {
        return (header != null && header.startsWith("Bearer "))
    }
}
