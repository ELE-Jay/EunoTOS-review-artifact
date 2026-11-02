/* SPDX-License-Identifier: ISC */
/*
 * Authors: Wei Chen <Wei.Chen@arm.com>
 *
 * Copyright (c) 2018 Arm Ltd.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <libfdt.h>

#include <uk/assert.h>
#include <uk/bitops.h>
#include <uk/ofw/fdt.h>
#include <uk/plat/console.h>
#include <uk/spinlock.h>
#include <uk/tty/pl011.h>

static uk_spinlock pl011_lock;

/*
 * PL011 UART base address
 * As we are using the PA = VA mapping, some SoC would set PA 0
 * as a valid address, so we can't use pl011_uart_bas == 0 to
 * indicate PL011 hasn't been initialized. In this case, we
 * use pl011_uart_initialized as an extra variable to check
 * whether the UART has been initialized.
 */
#if defined(CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE_BASE)
uint8_t pl011_uart_initialized = 1;
uint64_t pl011_uart_bas = CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE_BASE;
#else /* !CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE_BASE */
uint8_t pl011_uart_initialized;
uint64_t pl011_uart_bas;
#endif /* !CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE_BASE */

static void init_pl011(uint64_t bas)
{
	pl011_uart_bas = bas;

	/* Mask all interrupts */
	PL011_REG_WRITE(REG_UARTIMSC_OFFSET,
			PL011_REG_READ(REG_UARTIMSC_OFFSET) & 0xf800);

	/* Clear all interrupts */
	PL011_REG_WRITE(REG_UARTICR_OFFSET, 0x07ff);

	/* Disable UART for configuration */
	PL011_REG_WRITE(REG_UARTCR_OFFSET, 0);

	/* Select 8-bits data transmit and receive */
	PL011_REG_WRITE(REG_UARTLCR_H_OFFSET,
			(PL011_REG_READ(REG_UARTLCR_H_OFFSET) & 0xff00) |
			 LCR_H_WLEN8);

	/* Set baudrate for 115200 */
	PL011_REG_WRITE(REG_UARTIBRD_OFFSET, 2);    // 115200 baud
	PL011_REG_WRITE(REG_UARTFBRD_OFFSET, 0xB);

	/* Just enable UART and data transmit/receive */
	PL011_REG_WRITE(REG_UARTCR_OFFSET, CR_TXE | CR_UARTEN | CR_RXE);
}

void pl011_console_init(const void *dtb)
{
	int offset, val;
	uint64_t naddr, nsize;

	uk_pr_info("Serial initializing\n");
	offset = fdt_node_offset_by_compatible(dtb, -1, "arm,pl011");
	if (unlikely(offset < 0))
		UK_CRASH("No console UART found!\n");
	val = fdt_get_address(dtb, offset, 0, &naddr, &nsize);
	if (val < 0)
		UK_CRASH("Could not find proper address!\n");
	init_pl011((uint64_t)naddr);
	uk_pr_info("PL011 UART initialized\n");
	pl011_uart_initialized = 1;

	uk_spin_init(&pl011_lock);
}

int ukplat_coutd(const char *str, __u32 len)
{
	return ukplat_coutk(str, len);
}

static void pl011_write(char a)
{
	int flags;
	/*
	 * Avoid using the UART before base address initialized,
	 * or CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE is not enabled.
	 */
	if (!pl011_uart_initialized)
		return;

	ukplat_spin_lock_irqsave(&pl011_lock, flags);
	/* Wait until TX FIFO becomes empty */
	while (PL011_REG_READ(REG_UARTFR_OFFSET) & FR_TXFF)
		;

	PL011_REG_WRITE(REG_UARTDR_OFFSET, a & 0xff);

	ukplat_spin_unlock_irqrestore(&pl011_lock, flags);
}

static void pl011_putc(char a)
{
	if (a == '\n')
		pl011_write('\r');
	pl011_write(a);
}

/* Try to get data from pl011 UART without blocking */
static int pl011_getc(void)
{
	int read_val, flags;
	/*
	 * Avoid using the UART before base address initialized,
	 * or CONFIG_LIBUKTTY_PL011_EARLY_CONSOLE is not enabled.
	 */
	if (!pl011_uart_initialized)
		return -1;

	ukplat_spin_lock_irqsave(&pl011_lock, flags);

	/* If RX FIFO is empty, return -1 immediately */
	if (PL011_REG_READ(REG_UARTFR_OFFSET) & FR_RXFE)
		return -1;

	read_val = (int)(PL011_REG_READ(REG_UARTDR_OFFSET) & 0xff);
	ukplat_spin_unlock_irqrestore(&pl011_lock, flags);

	return read_val;
}

int ukplat_coutk(const char *buf, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		pl011_putc(buf[i]);
	return len;
}

int ukplat_cink(char *buf, unsigned int maxlen)
{
	int ret;
	unsigned int num = 0;

	while (num < maxlen && (ret = pl011_getc()) >= 0) {
		*(buf++) = (char)ret;
		num++;
	}

	return (int)num;
}
