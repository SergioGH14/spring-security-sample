package es.sergomz.securitysample.config

import es.sergomz.securitysample.config.jwt.JWTService
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class WebSecurityConfiguration(
    private val userDataDetailService: UserDataDetailService,
    private val jwtService: JWTService,
    private val passwordEncoder: PasswordEncoder
) :
    WebSecurityConfigurerAdapter() {

    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth!!.userDetailsService(userDataDetailService)
            .passwordEncoder(passwordEncoder)
    }

    override fun configure(http: HttpSecurity) {
        http
            .addFilter(AuthenticationFilter(jwtService, authenticationManager()))
            .addFilter(AuthorizationFilter(jwtService, authenticationManager()))
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

    }
}
