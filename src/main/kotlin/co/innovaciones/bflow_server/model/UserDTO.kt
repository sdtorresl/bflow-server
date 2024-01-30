package co.innovaciones.bflow_server.model

import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.OffsetDateTime


class UserDTO {

    var id: Long? = null

    @NotNull
    @Size(max = 255)
    var firstName: String? = null

    @NotNull
    @Size(max = 255)
    var lastName: String? = null

    @NotNull
    @Size(max = 255)
    var username: String? = null

    @NotNull
    @Size(max = 255)
    var password: String? = null

    @NotNull
    @Size(max = 255)
    var email: String? = null

    var recoveryToken: String? = null

    var tokenExpirationDate: OffsetDateTime? = null

}
