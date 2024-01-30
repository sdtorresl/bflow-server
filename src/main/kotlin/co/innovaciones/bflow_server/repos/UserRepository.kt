package co.innovaciones.bflow_server.repos

import co.innovaciones.bflow_server.domain.User
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*


interface UserRepository : JpaRepository<User, Long> {

    fun existsByUsernameIgnoreCase(username: String?): Boolean

    fun existsByEmailIgnoreCase(email: String?): Boolean

    fun findByUsernameIgnoreCase(username: String?): Optional<User>

    fun findByRecoveryToken(recoveryToken: String?): Optional<User>


}
