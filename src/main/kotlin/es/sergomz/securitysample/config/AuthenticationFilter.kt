package es.sergomz.securitysample.config

import com.fasterxml.jackson.databind.ObjectMapper
import es.sergomz.securitysample.config.jwt.JWTService
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.io.IOException
import java.time.LocalDateTime
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class AuthenticationFilter(private val jwtService: JWTService, authManager: AuthenticationManager) :
    UsernamePasswordAuthenticationFilter(authManager) {

    private val sessionStrategy:SessionAuthenticationStrategy = NullAuthenticatedSessionStrategy()


    init {
        setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher("/auth", "POST"))
    }

    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {

        var username = obtainUsername(request)
        var password = obtainPassword(request)

        username = username?.replace("\"".toRegex(), "") ?: ""

        password = password?.replace("\"".toRegex(), "") ?: ""

        username = username.trim { it <= ' ' }

        val authenticationToken = UsernamePasswordAuthenticationToken(username, password)
        return authenticationManager.authenticate(authenticationToken)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        require(authResult != null)
        val token: String = jwtService.createToken(authResult)
        response.addHeader(JWTService.HEADER, JWTService.TOKEN_PREFIX + token)
        val body: MutableMap<String, Any> = HashMap()
        body["token"] = token
        response.writer.write(ObjectMapper().writeValueAsString(body))
        response.status = 200
        response.contentType = "application/json"
    }


    override fun unsuccessfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        val body: MutableMap<String, Any> = HashMap()
        body["timestamp"] = LocalDateTime.now().toString()
        body["status"] = HttpStatus.UNAUTHORIZED
        body["error"] = failed.localizedMessage
        body["errorCode"] = HttpStatus.UNAUTHORIZED.name
        body["message"] = "The name, password or both are incorrect"
        body["path"] = "/auth"
        response.writer.write(ObjectMapper().writeValueAsString(body))
        response.status = 401
        response.contentType = "application/json"
    }

    override fun doFilter(req: ServletRequest?, res: ServletResponse?, chain: FilterChain) {
        val request = req as HttpServletRequest?
        val response = res as HttpServletResponse?
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response)
            return
        }
        if (logger.isDebugEnabled) {
            logger.debug("Request is to process authentication")
        }
        val authResult: Authentication
        try {
            authResult = attemptAuthentication(request, response)
            if (authResult == null) {
                // return immediately as subclass has indicated that it hasn't completed
                // authentication
                return
            }
            sessionStrategy.onAuthentication(authResult, request, response)
        } catch (failed: InternalAuthenticationServiceException) {
            logger.error(
                "An internal error occurred while trying to authenticate the user " + obtainUsername(request)
            )
            unsuccessfulAuthentication(request, response!!, failed)
            return
        } catch (failed: AuthenticationException) {
            // Authentication failed
            logger.error("Username not valid " + obtainUsername(request))
            unsuccessfulAuthentication(request, response!!, failed)
            return
        }

        // Authentication success
        val continueChainBeforeSuccessfulAuthentication = false
        if (continueChainBeforeSuccessfulAuthentication) {
            chain.doFilter(request, response)
        }
        successfulAuthentication(request, response!!, chain, authResult)
    }

}
