package es.sergomz.securitysample.config

import es.sergomz.securitysample.model.repository.UserDataRepository
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class UserDataDetailService(val userDataRepository: UserDataRepository) : UserDetailsService {

    override fun loadUserByUsername(username: String?): UserDetails {
        val userData = userDataRepository.findById(username!!).get()
        return User(
            userData.email, userData.password, mutableListOf<GrantedAuthority>()
        )
    }
}
