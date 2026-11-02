SECTIONS
{
	.uk_thread_inittab : {
		PROVIDE(_uk_thread_inittab_start = .);
		KEEP(*(SORT_BY_NAME(.uk_thread_inittab[0-9]*)))
		PROVIDE(_uk_thread_inittab_end = .);
	}
}
INSERT AFTER .rodata;
