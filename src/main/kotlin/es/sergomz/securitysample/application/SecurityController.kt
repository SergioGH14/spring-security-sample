package es.sergomz.securitysample.application

import es.sergomz.securitysample.config.jwt.JWTService
import es.sergomz.securitysample.model.UserDTO
import es.sergomz.securitysample.model.UserData
import es.sergomz.securitysample.model.repository.UserDataRepository
import org.springframework.security.access.annotation.Secured
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*

@RestController("/users")
class SecurityController(val userDataRepository: UserDataRepository, val passwordEncoder: PasswordEncoder, val jwtService: JWTService) {

    @GetMapping("/email")
    fun getEmail(@RequestHeader("Authorization") token: String): UserData {
        return userDataRepository.getById(jwtService.getUserName(token))
    }

    @PostMapping
    fun addUser(@RequestBody user: UserDTO) {
        userDataRepository.save(UserData(user.email, passwordEncoder.encode(user.password)))
    }
}
