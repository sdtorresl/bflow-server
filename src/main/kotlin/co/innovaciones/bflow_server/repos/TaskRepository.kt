package co.innovaciones.bflow_server.repos

import co.innovaciones.bflow_server.domain.File
import co.innovaciones.bflow_server.domain.Task
import org.springframework.data.jpa.repository.JpaRepository


interface TaskRepository : JpaRepository<Task, Long> {

    fun findAllByAttachments(`file`: File): List<Task>

}