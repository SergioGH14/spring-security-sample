package es.sergomz.securitysample.model

import javax.persistence.Id

data class UserDTO(
    val email: String,
    val password: String
)
