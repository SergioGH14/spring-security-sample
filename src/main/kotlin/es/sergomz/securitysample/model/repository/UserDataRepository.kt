package es.sergomz.securitysample.model.repository

import es.sergomz.securitysample.model.UserData
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserDataRepository : JpaRepository<UserData, String>
