#include <uk/arch/limits.h>
#include <uk/plat/common/common.lds.h>

#define RAM_BASE_ADDR	CONFIG_RAM_BASE_ADDR
#define PROTO_RESERVED	0x100000

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

PHDRS
{
	text PT_LOAD FLAGS(PHDRS_PF_RX);
	rodata PT_LOAD FLAGS(PHDRS_PF_R);
	data PT_LOAD;
	tls PT_TLS;
	tls_load PT_LOAD;
	stack PT_GNU_STACK FLAGS(PHDRS_PF_RW);
}

SECTIONS
{
	. = RAM_BASE_ADDR;
	_start_ram_addr = .;
#ifdef CONFIG_BOOT_PROTO_LXBOOT
	. = . + PROTO_RESERVED;
#endif
	_base_addr = .;

	/* Code */
	_text = .;
	.text :
	{
		KEEP(*(.text.boot))
		*(.text)
		*(.text.*)
	} :text
	. = ALIGN(__PAGE_SIZE);
	_etext = .;

	/* Read-only data */
	. = ALIGN(__PAGE_SIZE);
	_rodata = .;
	.rodata :
	{
		*(.rodata)
		*(.rodata.*)
	} :rodata

	EXCEPTION_SECTIONS

	CTORTAB_SECTION

	INITTAB_SECTION

	ENTRYTAB_SECTION

	EVENTTAB_SECTION

	_erodata = .;

	/* Constructor tables (read-only) */
	. = ALIGN(0x8);
	_ctors = .;
	.preinit_array : {
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP (*(.preinit_array))
		PROVIDE_HIDDEN (__preinit_array_end = .);
	}

	. = ALIGN(0x8);
	.init_array : {
		PROVIDE_HIDDEN (__init_array_start = .);
		KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) \
		SORT_BY_INIT_PRIORITY(.ctors.*)))
		KEEP (*(.init_array .ctors))
		PROVIDE_HIDDEN (__init_array_end = .);
	}
	_ectors = .;
	. = ALIGN(__PAGE_SIZE);

	TLS_SECTIONS

	DATA_SECTIONS

#ifdef CONFIG_STATIC_PGTABLE
	STATIC_PGTABLE_SECTION
#endif

	_end = .;

	.comment       0 : { *(.comment) }
	DEBUG_SYMBOLS

	DISCARDS
}
__bss_size = (__bss_end - __bss_start)>>3;
