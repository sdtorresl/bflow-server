package co.innovaciones.bflow_server.service

import co.innovaciones.bflow_server.domain.User
import co.innovaciones.bflow_server.model.UserDTO
import co.innovaciones.bflow_server.repos.UserRepository
import co.innovaciones.bflow_server.util.NotFoundException
import org.springframework.data.domain.Sort
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service


@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {

    fun findAll(): List<UserDTO> {
        val users = userRepository.findAll(Sort.by("id"))
        return users.stream()
                .map { user -> mapToDTO(user, UserDTO()) }
                .toList()
    }

    fun `get`(id: Long): UserDTO = userRepository.findById(id)
            .map { user -> mapToDTO(user, UserDTO()) }
            .orElseThrow { NotFoundException() }

    fun `get`(username: String?): UserDTO = userRepository.findByUsernameIgnoreCase(username)
            .map { user -> mapToDTO(user, UserDTO()) }
            .orElseThrow { NotFoundException() }

    fun getUserByToken(token: String): UserDTO = userRepository.findByRecoveryToken(token)
            .map { user -> mapToDTO(user, UserDTO()) }
            .orElseThrow { NotFoundException() }

    fun create(userDTO: UserDTO): Long {
        val user = User()
        mapToEntity(userDTO, user)
        return userRepository.save(user).id!!
    }

    fun update(id: Long, userDTO: UserDTO) {
        val user = userRepository.findById(id)
                .orElseThrow { NotFoundException() }
        mapToEntity(userDTO, user)
        userRepository.save(user)
    }
    fun delete(id: Long) {
        userRepository.deleteById(id)
    }

    private fun mapToDTO(user: User, userDTO: UserDTO): UserDTO {
        userDTO.id = user.id
        userDTO.firstName = user.firstName
        userDTO.lastName = user.lastName
        userDTO.username = user.username
        userDTO.password = user.password
        userDTO.email = user.email
        userDTO.recoveryToken = user.recoveryToken
        userDTO.tokenExpirationDate = user.tokenExpirationDate


        return userDTO
    }

    private fun mapToEntity(userDTO: UserDTO, user: User): User {
        user.firstName = userDTO.firstName
        user.lastName = userDTO.lastName
        user.username = userDTO.username
        user.password = passwordEncoder.encode(userDTO.password)
        user.email = userDTO.email
        user.recoveryToken = userDTO.recoveryToken
        user.tokenExpirationDate = userDTO.tokenExpirationDate

        return user
    }

    fun usernameExists(username: String?): Boolean =
            userRepository.existsByUsernameIgnoreCase(username)

    fun emailExists(email: String?): Boolean = userRepository.existsByEmailIgnoreCase(email)

}
