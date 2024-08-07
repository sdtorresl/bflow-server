package co.innovaciones.bflow_server.service

import co.innovaciones.bflow_server.domain.Item
import co.innovaciones.bflow_server.model.ItemDTO
import co.innovaciones.bflow_server.repos.CategoryRepository
import co.innovaciones.bflow_server.repos.ContactRepository
import co.innovaciones.bflow_server.repos.ItemRepository
import co.innovaciones.bflow_server.repos.JobRepository
import co.innovaciones.bflow_server.repos.PurchaseOrderRepository
import co.innovaciones.bflow_server.util.NotFoundException
import org.springframework.data.domain.Sort
import org.springframework.stereotype.Service


@Service
class ItemService(
    private val itemRepository: ItemRepository,
    private val purchaseOrderRepository: PurchaseOrderRepository,
    private val contactRepository: ContactRepository,
    private val categoryRepository: CategoryRepository,
    private val jobRepository: JobRepository
) {

    fun findAll(): List<ItemDTO> {
        val items = itemRepository.findAll(Sort.by("id"))
        return items.stream()
                .map { item -> mapToDTO(item, ItemDTO()) }
                .toList()
    }

    fun findByJob(jobId: Long): List<ItemDTO> {
        val job = jobRepository.findById(jobId).get()
        val items = itemRepository.findAllByJob(job, Sort.by("name"))
        return items.stream()
            .map { item -> mapToDTO(item, ItemDTO()) }
            .toList()
    }

    fun `get`(id: Long): ItemDTO = itemRepository.findById(id)
            .map { item -> mapToDTO(item, ItemDTO()) }
            .orElseThrow { NotFoundException() }

    fun create(itemDTO: ItemDTO): Long {
        val item = Item()
        mapToEntity(itemDTO, item)
        return itemRepository.save(item).id!!
    }

    fun createAll(itemsDTO: List<ItemDTO>): List<Long?> {
        val items = itemsDTO.map { mapToEntity(it, Item()) }

        return itemRepository.saveAll(items).map { it.id }
    }

    fun update(id: Long, itemDTO: ItemDTO) {
        val item = itemRepository.findById(id)
                .orElseThrow { NotFoundException() }
        mapToEntity(itemDTO, item)
        itemRepository.save(item)
    }

    fun delete(id: Long) {
        itemRepository.deleteById(id)
    }

    fun mapToDTO(item: Item, itemDTO: ItemDTO): ItemDTO {
        itemDTO.id = item.id
        itemDTO.name = item.name
        itemDTO.description = item.description
        itemDTO.unitPrice = item.unitPrice
        itemDTO.vat = item.vat
        itemDTO.price = item.price
        itemDTO.units = item.units
        itemDTO.units = item.units
        itemDTO.purchaseOrder = item.purchaseOrder?.id
        itemDTO.supplier = item.supplier?.id
        itemDTO.category = item.category?.id
        itemDTO.job = item.job?.id
        itemDTO.measure = item.measure
        return itemDTO
    }

    private fun mapToEntity(itemDTO: ItemDTO, item: Item): Item {
        item.name = itemDTO.name
        item.description = itemDTO.description
        item.unitPrice = if(itemDTO.unitPrice != null) itemDTO.unitPrice!! else 0.0
        item.vat = if(itemDTO.vat != null) itemDTO.vat!! else 0.0
        //item.price = if(itemDTO.price != null) itemDTO.price!! else 0.0
        item.units = if(itemDTO.units != null) itemDTO.units!! else 0
        item.measure = itemDTO.measure
        val purchaseOrder = if (itemDTO.purchaseOrder == null) null else
                purchaseOrderRepository.findById(itemDTO.purchaseOrder!!)
                .orElseThrow { NotFoundException("purchaseOrder not found") }
        item.purchaseOrder = purchaseOrder
        val supplier = if (itemDTO.supplier == null) null else
                contactRepository.findById(itemDTO.supplier!!)
                .orElseThrow { NotFoundException("supplier not found") }
        item.supplier = supplier
        val category = if (itemDTO.category == null) null else
                categoryRepository.findById(itemDTO.category!!)
                .orElseThrow { NotFoundException("category not found") }
        item.category = category
        val job = if (itemDTO.job == null) null else jobRepository.findById(itemDTO.job!!)
                .orElseThrow { NotFoundException("job not found") }
        item.job = job
        return item
    }

    fun supplierExists(id: Long?): Boolean = itemRepository.existsBySupplierId(id)

    fun categoryExists(id: Long?): Boolean = itemRepository.existsByCategoryId(id)

}
