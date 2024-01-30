package co.innovaciones.bflow_server.model

import jakarta.validation.constraints.Size
import org.jetbrains.annotations.NotNull

class NewPassDTO {

    @NotNull
    @Size(max = 38, min = 32)
    val token: String? = null

    @NotNull
    @Size(max = 255, min = 8)
    val password: String? = null


}