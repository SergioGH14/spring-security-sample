package es.sergomz.securitysample.model

import javax.persistence.Entity
import javax.persistence.Id

@Entity
data class UserData(
    @Id
    val email: String,
    val password: String
)
