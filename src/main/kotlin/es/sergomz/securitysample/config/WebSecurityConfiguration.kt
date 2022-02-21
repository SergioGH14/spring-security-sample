package es.sergomz.securitysample.config

import es.sergomz.securitysample.config.jwt.JWTService
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.AuthenticationException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Service
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@EnableWebSecurity
@Configuration
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
            .authorizeRequests {
                it.antMatchers(HttpMethod.POST, "/users").permitAll()
                    .antMatchers("/auth").permitAll()
            }
            .addFilter(AuthenticationFilter(jwtService, authenticationManager()))
            .addFilter(AuthorizationFilter(jwtService, authenticationManager()))
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

    }
}
