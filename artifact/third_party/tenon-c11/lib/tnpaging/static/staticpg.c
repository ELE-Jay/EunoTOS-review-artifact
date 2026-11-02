#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <staticpg.h>

/* Below is a simple queue implementation used in static page tables.
 * It is applied when writing the static page table to a file using
 * a breadth-first traversal.
 */
typedef struct queue_node {
	void			  *data; /* Used to store page table pointers */
	struct queue_node *next; /* Points to the next queue node */
} queue_node;

typedef struct {
	queue_node *front; /* points to the first queue node */
	queue_node *rear;  /* points to the tail queue node */
} queue;

static void init_queue(queue *q)
{
	if (q)
		q->front = q->rear = NULL;
}

static bool is_queue_empty(const queue *q)
{
	return !q || q->front == NULL;
}

static bool enqueue(queue *q, void *data)
{
	if (!q)
		return false;

	queue_node *new_node = (queue_node *)malloc(sizeof(queue_node));

	if (!new_node)
		return false;

	new_node->data = data;
	new_node->next = NULL;

	if (q->rear)
		q->rear->next = new_node;
	else
		q->front = new_node;
	q->rear = new_node;
	return true;
}

static void *dequeue(queue *q)
{
	if (is_queue_empty(q))
		return NULL;

	queue_node *temp = q->front;
	void	   *data = temp->data;

	q->front = q->front->next;

	if (!q->front)
		q->rear = NULL;

	free(temp);
	return data;
}

static void destroy_queue(queue *q)
{
	if (!q)
		return;

	while (q->front) {
		queue_node *temp = q->front;

		q->front = q->front->next;
		free(temp);
	}
	q->rear = NULL;
}

/* Recursively free all levels of a static page table */
static void free_page_table(page_table *root_table)
{
	if (!root_table) {
		printf("Error: root_table is NULL\n");
		return;
	}

	for (size_t i = 0; i < PTE_PER_LEVEL; i++) {
		if (root_table->entries[i].pte_table) {
			page_table *next_table =
				(page_table *)(root_table->entries[i].data);

			if (next_table)
				free_page_table(next_table);
		}
	}
	free(root_table);
}

/* Convert memory region flags to attributes for the page table entry */
static uint64_t memrf_to_attr(uint16_t flags)
{
	uint64_t prot = 0x0;
	uint16_t mask;

	mask = UKPLAT_MEMRF_EXTRACT_SHAREABLE(flags);
	switch (mask) {
	case UKPLAT_MEMRF_SHAREABLE_NS:
		prot |= PTE_ATTR_SH(PTE_ATTR_SH_NS);
		break;
	case UKPLAT_MEMRF_SHAREABLE_IS:
		prot |= PTE_ATTR_SH(PTE_ATTR_SH_IS);
		break;
	case UKPLAT_MEMRF_SHAREABLE_OS:
		prot |= PTE_ATTR_SH(PTE_ATTR_SH_OS);
		break;
	default:
		prot |= PTE_ATTR_SH(PTE_ATTR_SH_IS);
		break;
	}

	mask = UKPLAT_MEMRF_EXTRACT_MAIR(flags);
	switch (mask) {
	case UKPLAT_MEMRF_MAIR_NORMAL_WB:
		prot |= PTE_ATTR_IDX(NORMAL_WB);
		break;
	case UKPLAT_MEMRF_MAIR_NORMAL_WT:
		prot |= PTE_ATTR_IDX(NORMAL_WT);
		break;
	case UKPLAT_MEMRF_MAIR_NORMAL_NC:
		prot |= PTE_ATTR_IDX(NORMAL_NC);
		break;
	case UKPLAT_MEMRF_MAIR_DEVICE_nGnRnE:
		prot |= PTE_ATTR_IDX(DEVICE_nGnRnE);
		break;
	case UKPLAT_MEMRF_MAIR_DEVICE_nGnRE:
		prot |= PTE_ATTR_IDX(DEVICE_nGnRE);
		break;
	case UKPLAT_MEMRF_MAIR_DEVICE_GRE:
		prot |= PTE_ATTR_IDX(DEVICE_GRE);
		break;
	case UKPLAT_MEMRF_MAIR_NORMAL_WB_TAGGED:
		prot |= PTE_ATTR_IDX(NORMAL_WB_TAGGED);
		break;
	default:
		prot |= PTE_ATTR_IDX(NORMAL_WB);
		break;
	}

	prot |= (flags & UKPLAT_MEMRF_WRITE) ? PTE_ATTR_AP(PTE_ATTR_AP_RW) :
										   PTE_ATTR_AP(PTE_ATTR_AP_RO);

	if (flags & UKPLAT_MEMRF_UXN)
		prot |= PTE_ATTR_UXN;
	else if (!(flags & UKPLAT_MEMRF_EXECUTE))
		prot |= PTE_ATTR_XN;

	mask = UKPLAT_MEMRF_EXTRACT_ACCESS(flags);
	switch (mask) {
	case UKPLAT_MEMRF_ACCESS_AF:
		prot |= PTE_ATTR_AF;
		break;
	case UKPLAT_MEMRF_ACCESS_nG:
		prot |= PTE_ATTR_nG;
		break;
	case UKPLAT_MEMRF_ACCESS_CONTIGUOUS:
		prot |= PTE_ATTR_CONTIGUOUS;
		break;
	default:
		break;
	}

	if (UKPLAT_MEMRF_EXTRACT_LEVEL(flags) != UKPLAT_MEMRF_LEVEL_PAGE)
		prot |= PTE_TYPE_BLOCK;
	else
		prot |= PTE_TYPE_PAGE;

	return prot;
}

/* Extract the page table level from memory region flags */
static uint64_t memrf_to_level(uint16_t flags)
{
	return UKPLAT_MEMRF_EXTRACT_LEVEL(flags);
}

/**
 * insert_to_page_table - Map a physical address range to a virtual address
 * range in a page table.
 * @root_table: Pointer to the root page table.
 * @pbase: Starting physical address to map.
 * @vbase: Starting virtual address for the mapping.
 * @len: Length of the address range to map.
 * @attr: Attributes for the page table entries (e.g., permissions, cache
 * flags).
 * @lvl: Page table level to use for the mapping (e.g., PGD, PUD, PMD, PTE).
 *
 * Returns:
 *  - Pointer to the updated root page table on success.
 *  - NULL on failure (e.g., memory allocation failure), with an error message
 * printed to the console.
 */
static page_table *insert_to_page_table(page_table *root_table, uint64_t pbase,
										uint64_t vbase, uint64_t len,
										uint64_t attr, int lvl)
{
	uint64_t entries_size  = (1UL << (PAGE_SHIFT + lvl * 9));
	uint64_t page_mask	   = ~(entries_size - 1);
	uint64_t vaddr_end	   = (vbase + len - 1) & page_mask;
	uint64_t current_vaddr = vbase & page_mask;
	uint64_t current_paddr = pbase;

	while (current_vaddr <= vaddr_end) {
		page_table *current_table = root_table;
		int indices[4] = { (current_vaddr >> PGD_SHIFT) & (PTE_PER_LEVEL - 1),
						   (current_vaddr >> PUD_SHIFT) & (PTE_PER_LEVEL - 1),
						   (current_vaddr >> PMD_SHIFT) & (PTE_PER_LEVEL - 1),
						   (current_vaddr >> PAGE_SHIFT) &
							   (PTE_PER_LEVEL - 1) };

		for (int i = 0; i < 3 - lvl; i++) {
			int idx = indices[i];

			if (!current_table->entries[idx].pte_table) {
				page_table *new_table = calloc(1, sizeof(page_table));

				if (!new_table) {
					printf("Failed to allocate page table\n");
					return NULL;
				}
				current_table->entries[idx].data	  = (uint64_t)new_table;
				current_table->entries[idx].pte_table = true;
			}
			current_table = (page_table *)current_table->entries[idx].data;
		}
		int target_idx = indices[3 - lvl];

		current_table->entries[target_idx].data		 = current_paddr | attr;
		current_table->entries[target_idx].pte_table = false;

		current_vaddr += entries_size;
		current_paddr += entries_size;
	}

	return root_table;
}

/**
 * write_page_table_queue - Write a page table hierarchy to a binary file using
 * a queue.
 * @root_table: Pointer to the root page table.
 * @filename: Path to the output binary file.
 * @base_addr: Starting base address for page table entries.
 *
 * Returns:
 *  - true: Success, and the page table hierarchy is written to the file.
 *  - false: Failure, with an error message printed to the console.
 */
static bool write_page_table_queue(page_table *root_table, const char *filename,
								   uint64_t base_addr)
{
	FILE *file = fopen(filename, "wb");

	if (!file) {
		perror("Failed to open file for writing");
		return false;
	}

	queue q;

	init_queue(&q);
	if (!enqueue(&q, root_table)) {
		printf("Failed to enqueue root table\n");
		fclose(file);
		return false;
	}
	uint64_t next_pgtable_addr = base_addr + PTE_PER_LEVEL * sizeof(uint64_t);

	while (!is_queue_empty(&q)) {
		page_table *current_table = (page_table *)dequeue(&q);

		if (!current_table) {
			printf("Failed to dequeue page table\n");
			goto write_failure;
		}

		uint64_t binary_data[PTE_PER_LEVEL] = { 0 };

		for (size_t i = 0; i < PTE_PER_LEVEL; i++) {
			if (current_table->entries[i].pte_table) {
				page_table *next_table =
					(page_table *)current_table->entries[i].data;

				if (!enqueue(&q, next_table)) {
					printf("Failed to enqueue next table\n");
					goto write_failure;
				}

				binary_data[i] = next_pgtable_addr | PTE_TYPE_TABLE;
				next_pgtable_addr += PTE_PER_LEVEL * sizeof(uint64_t);
			} else {
				binary_data[i] = current_table->entries[i].data;
			}
		}

		if (fwrite(binary_data, sizeof(binary_data), 1, file) != 1) {
			perror("Failed to write binary data to file");
			goto write_failure;
		}
	}

	fclose(file);
	destroy_queue(&q);
	return true;

write_failure:
	fclose(file);
	destroy_queue(&q);
	return false;
}

/* Determine the page table level for a given mapping */
static int choose_pgtable_level(uint64_t vbase, uint64_t size, int lvl)
{
	if (lvl < 0 || lvl > 2) {
		if ((vbase % PUD_SIZE == 0) && (size % PUD_SIZE == 0))
			lvl = 2;
		else if ((vbase % PMD_SIZE == 0) && (size % PMD_SIZE == 0))
			lvl = 1;
		else
			lvl = 0;
	}

	return lvl;
}

/**
 * get_section - Locate a specific section in an ELF file.
 * @fd: File descriptor of the ELF file.
 * @elf: Pointer to the ELF object.
 * @target_section_name: Name of the section to locate.
 * @scn: Output pointer to the located section, if found.
 *
 * Returns:
 *  - 0 on success, with *scn pointing to the target section.
 *  - -1 on failure, with an error message printed to stderr.
 */
static int get_section(Elf *elf, char *target_section_name, Elf_Scn **scn)
{
	char	 *section_name = NULL;
	Elf_Scn	 *next_scn	   = NULL;
	size_t	  shstrndx;
	GElf_Shdr shdr;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		printf("elf_getshdrstrndx() failed: %s\n", elf_errmsg(-1));
		return -1;
	}

	while ((next_scn = elf_nextscn(elf, next_scn)) != NULL) {
		if (gelf_getshdr(next_scn, &shdr) == NULL) {
			printf("gelf_getshdr() failed: %s\n", elf_errmsg(-1));
			continue;
		}

		section_name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!section_name) {
			printf("elf_strptr() failed: %s\n", elf_errmsg(-1));
			continue;
		}

		if (strcmp(section_name, target_section_name) == 0) {
			*scn = next_scn;
			return 0;
		}
	}

	printf("Not found target section: %s\n", target_section_name);
	return -1;
}

int compare_by_pbase(const void *a, const void *b)
{
	const struct ukplat_memregion_desc *m1 = a;
	const struct ukplat_memregion_desc *m2 = b;

	if (m1->pbase < m2->pbase)
		return -1;
	if (m1->pbase > m2->pbase)
		return 1;
	return 0;
}

/**
 * create_pgtable - Generate a page table from static memory region array by
 *					an ELF file and save it to an output file.
 * @filename: Path to the input ELF file containing memory region information.
 * @out_filename: Path to the output file to write the generated page table.
 *
 * Returns:
 *  - 0: Success.
 *  - -1: Failure, with error messages printed to the console.
 */
static int create_pgtable(const char *filename, const char *out_filename)
{
	int			fd			 = -1;
	int			count		 = 0;
	Elf		   *elf			 = NULL;
	Elf_Data   *section_data = NULL;
	Elf_Scn	   *scn			 = NULL;
	int			err			 = 0;
	page_table *pgtable		 = calloc(1, sizeof(page_table));
	uint64_t pbase, vbase, len, prot, level;
	uint16_t flags;

	if (!filename || !out_filename) {
		printf("Invalid file path\n");
		return -1;
	}

	if (!pgtable) {
		printf("Failed to allocate page table\n");
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("Failed to open file");
		free_page_table(pgtable);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("ELF library initialization failed: %s\n", elf_errmsg(-1));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		printf("elf_begin() failed: %s\n", elf_errmsg(-1));
		close(fd);
		free_page_table(pgtable);
		return -1;
	}

	if (!!get_section(elf, PGTABLE_INFO_SECTION, &scn)) {
		err = -1;
		goto clean_up;
	}

	section_data = elf_getdata(scn, NULL);
	if (!section_data) {
		printf("Target section not found: %s\n", PGTABLE_INFO_SECTION);
		err = -1;
		goto clean_up;
	}

	count = section_data->d_size / sizeof(struct ukplat_memregion_desc);
	struct ukplat_memregion_desc *regions =
		(struct ukplat_memregion_desc *)section_data->d_buf;

	/* Make sure that the memregion is orderly */
	qsort(regions, count, sizeof(struct ukplat_memregion_desc),
		  compare_by_pbase);

	/* Check whether the Memregion is overlapped */
	for (int i = 0; i + 1 < count; i++) {
		struct ukplat_memregion_desc *ml, *mr;

		ml = &regions[i];
		mr = &regions[i + 1];

		ASSERT_VALID_MRD(ml);
		ASSERT_VALID_MRD(mr);

		if (RANGE_OVERLAP(ml->pbase, ml->pg_count * PAGE_SIZE, mr->pbase,
						  mr->pg_count * PAGE_SIZE)) {
			printf("Static memregion overlap!\n");
			print_memregion(ml);
			print_memregion(mr);
			err = -1;
			goto clean_up;
		}
	}

	for (int i = 0; i < count; ++i) {
		pbase = regions[i].pbase;
		vbase = regions[i].vbase;
		len   = regions[i].len;
		flags = regions[i].flags;
		prot  = memrf_to_attr(flags);
		level = memrf_to_level(flags);

		level = choose_pgtable_level(vbase, len, level);
		if (!insert_to_page_table(pgtable, pbase, vbase, len, prot, level)) {
			printf("Failed to insert into page table\n");
			err = -1;
			goto clean_up;
		}
	}

#if CONFIG_PAGING
	if (!!get_section(elf, PGTABLE_INFO_DIRECT_SECTION, &scn)) {
		err = -1;
		goto clean_up;
	}

	section_data = elf_getdata(scn, NULL);
	if (!section_data) {
		printf("Target section not found: %s\n", PGTABLE_INFO_DIRECT_SECTION);
		err = -1;
		goto clean_up;
	}

	regions = (struct ukplat_memregion_desc *)section_data->d_buf;

	ASSERT_VALID_MRD(regions);

	pbase = regions[0].pbase;
	vbase = regions[0].vbase;
	len	  = regions[0].len;
	flags = regions[0].flags;
	prot  = memrf_to_attr(flags);
	level = memrf_to_level(flags);

	level = choose_pgtable_level(vbase, len, level);
	if (!insert_to_page_table(pgtable, pbase, vbase, len, prot, level)) {
		printf("Failed to insert into page table\n");
		err = -1;
		goto clean_up;
	}
#endif

	uint64_t base_addr = 0x0;

	if (!write_page_table_queue(pgtable, out_filename, base_addr)) {
		printf("Failed to write page table to output\n");
		err = -1;
	}

clean_up:
	free_page_table(pgtable);
	elf_end(elf);
	close(fd);
	return err;
}

/**
 * get_pt_address - Parse the ELF file and retrieve the starting address of the
 * page table section.
 * @filename: Path to the input ELF file.
 * @base_addr: Pointer to store the starting address of the page table section.
 *
 * Returns:
 *  - 0: Success, and the page table section address is stored in *base_addr.
 *  - -1: Failure, with an error message printed to the console.
 */
static int get_pt_address(const char *filename, uint64_t *base_addr)
{
	int		  fd  = -1;
	Elf		 *elf = NULL;
	Elf_Scn	 *scn = NULL;
	GElf_Shdr shdr;
	int		  err = 0;

	*base_addr = 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("Error opening file");
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("ELF library initialization failed: %s\n", elf_errmsg(-1));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		printf("Error: elf_begin failed: %s\n", elf_errmsg(-1));
		close(fd);
		return -1;
	}

	if (!!get_section(elf, PGTABLE_SECTION, &scn)) {
		err = -1;
		goto clean;
	}

	if (!gelf_getshdr(scn, &shdr)) {
		err = -1;
		goto clean;
	}

	*base_addr = shdr.sh_addr;

	if (*base_addr == 0) {
		printf("Error: Section %s not found in %s\n", PGTABLE_SECTION,
			   filename);
		err = -1;
	}

clean:
	elf_end(elf);
	close(fd);
	return err;
}

/**
 * update_pgtable - Update the page table entries in a binary file.
 * @file_name: Path to the binary file containing page table entries.
 * @base_addr: Base address to be added to page table entries of type
 * PTE_TYPE_TABLE.
 *
 * Returns:
 *  - 0: Success, and the file is updated with the new page table entries.
 *  - -1: Failure, with an error message printed to the console.
 */
static int update_pgtable(const char *file_name, const char *update_path,
						  uint64_t base_addr)
{
	FILE *file = fopen(file_name, "r+b");
	FILE *update_file = fopen(update_path, "wb");
	int	  err		  = 0;

	if (!file) {
		fprintf(stderr, "Error opening file: %s\n", file_name);
		return -1;
	}

	if (!update_file) {
		fprintf(stderr, "Error opening update file: %s.update\n", update_path);
		fclose(file);
		return -1;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fprintf(stderr, "Error seeking to end of file for %s\n", file_name);
		err = -1;
		goto update_failure;
	}

	long file_size = ftell(file);

	if (file_size < 0 || file_size % 8 != 0) {
		fprintf(stderr,
				"Invalid file size: %ld bytes (must be multiple of 8)\n",
				file_size);
		err = -1;
		goto update_failure;
	}

	rewind(file);

	size_t	 num_entries			= file_size / 8;
	size_t	 entries_per_block		= BLOCK_SIZE / 8;
	uint64_t buffer[BLOCK_SIZE / 8];
	size_t	 processed_entries		= 0;

	while (processed_entries < num_entries) {
		size_t entries_to_process =
			(processed_entries + entries_per_block <= num_entries) ?
				entries_per_block :
				(num_entries - processed_entries);

		if (fread(buffer, 8, entries_to_process, file) != entries_to_process) {
			perror("Error reading file");
			err = -1;
			goto update_failure;
		}

		for (size_t i = 0; i < entries_to_process; i++)
			if ((buffer[i] & 0xFFF) == PTE_TYPE_TABLE)
				buffer[i] += base_addr;

		if (fwrite(buffer, 8, entries_to_process, update_file) !=
			entries_to_process) {
			perror("Error writing to file");
			err = -1;
			goto update_failure;
		}

		processed_entries += entries_to_process;
	}

update_failure:
	fclose(file);
	fclose(update_file);
	return err;
}

void print_usage(const char *progname)
{
	printf(
		"Usage: %s [create|update] <kernel_path> <out_path> [update_path|]\n",
		progname);
	printf("Options:\n");
	printf(
		"  create  Create a static page table using kernel_path and write to out_path\n");
	printf(
		"  update  Update a static page table using kernel_path and modify out_path\n");
}

int main(int argc, char *argv[])
{
	if (argc > 5) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	const char *command		= argv[1];
	const char *kernel_path = argv[2];
	const char *out_path	= argv[3];

	if (strcmp(command, "create") == 0) {
		if (create_pgtable(kernel_path, out_path) != 0) {
			printf("Failed to create static page table.\n");
			return EXIT_FAILURE;
		}
	} else if (strcmp(command, "update") == 0) {
		uint64_t base_addr = 0;
		const char *update_path = argv[4];

		if (get_pt_address(kernel_path, &base_addr) != 0) {
			printf("Failed to get page table base address.\n");
			return EXIT_FAILURE;
		}
		if (update_pgtable(out_path, update_path, base_addr) != 0) {
			printf("Failed to update static page table.\n");
			return EXIT_FAILURE;
		}
	} else {
		printf("Unknown command: %s\n", command);
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
