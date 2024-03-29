package co.innovaciones.bflow_server.model

import co.innovaciones.bflow_server.model.validators.WithinParentDateRange
import jakarta.validation.constraints.Max
import jakarta.validation.constraints.Min
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.LocalDate


@WithinParentDateRange
open class TaskDTO {

    var id: Long? = null

    @NotNull
    @Size(max = 255)
    var name: String? = null

    @NotNull
    var startDate: LocalDate? = null

    var endDate: LocalDate? = null

    @NotNull
    var progress: Double? = null

    @NotNull
    var status: TaskStatus? = null

    @NotNull
    var stage: TaskStage? = null

    var parentTask: Long? = null

    var attachments: List<Long>? = null

    @NotNull
    var job: Long? = null

    var description: String? = null

    @Min(0)
    @Max(10000)
    var order: Int = 0

}
