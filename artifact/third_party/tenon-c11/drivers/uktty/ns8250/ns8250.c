/*
 * Copyright 2024 Hangzhou Yingyi Technology Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <libfdt.h>

#include <uk/assert.h>
#include <uk/config.h>
#include <uk/ofw/fdt.h>
#include <uk/plat/console.h>
#include <uk/spinlock.h>

static uk_spinlock ns8250_lock;

#define NS8250_THR_OFFSET	0x00U
#define NS8250_RBR_OFFSET	0x00U
#define NS8250_DLL_OFFSET	0x00U
#define NS8250_DLM_OFFSET	0x01U
#define NS8250_IER_OFFSET	0x01U
#define NS8250_IIR_OFFSET	0x02U
#define NS8250_FCR_OFFSET	0x02U
#define NS8250_LCR_OFFSET	0x03U
#define NS8250_MCR_OFFSET	0x04U
#define NS8250_LSR_OFFSET	0x05U
#define NS8250_MSR_OFFSET	0x06U

#define NS8250_MCR_DTR		0x01U	/* DTR */
#define NS8250_MCR_RTS		0x02U	/* RTS */
#define NS8250_MCR_SET		(NS8250_MCR_DTR |	\
				NS8250_MCR_RTS)

#define NS8250_LCR_8N1		0x03U
#define NS8250_LCR_DLAB	0x80U
#define NS8250_IIR_NO_INT	0x01U
#define NS8250_FCR_FIFO_EN	0x01U
#define NS8250_FCR_RXSR	0x02U /* Receiver soft reset */
#define NS8250_FCR_TXSR	0x04U /* Transmitter soft reset */
#define NS8250_LSR_RX_EMPTY	0x01U
#define NS8250_LSR_TX_EMPTY	0x40U
#define NS8250_FCR_DEFVAL	(NS8250_FCR_FIFO_EN |	\
				NS8250_FCR_RXSR  |	\
				NS8250_FCR_TXSR)

static __u8 ns8250_uart_initialized;
static __u64 ns8250_uart_base;

/* Early console node name in DTB, help to find related info */
static char *earlycon_node_name =
CONFIG_LIBTNTTY_EARLY_PRINT_NS8250_CONSOLE_NAME;

static __u32 ns8250_uart_freq;

/* The register shift. Default is 0 (device-tree spec v0.4 Sect. 4.2.2) */
static __u32 ns8250_reg_shift;

/* The register width. Default is 1 (8-bit register width) */
static __u32 ns8250_reg_width = 0x01;

static __u32 ns8250_baudrate = 115200;

static __u32 ns8250_mode_x_div = 16;

/* Macros to access ns16550 registers with base address and reg shift */
#define NS8250_REG(r) (ns8250_uart_base + (r << ns8250_reg_shift))

/* Macros to extract int shift/width infos */
#define EXTRACT_HIGH_BITS(x) ((__u32)((x) & 0xFFFFFFFF) >> 24)

static inline __u32 ns8250_reg_read(__u32 reg)
{
	int flags;

	ukplat_spin_lock_irqsave(&ns8250_lock, flags);

	__u32 ret;

	switch (ns8250_reg_width) {
	case 1:
		ret = ioreg_read8((__u8 *)NS8250_REG(reg)) & 0xff;
		break;
	case 2:
		ret = ioreg_read16((__u16 *)NS8250_REG(reg)) & 0xffff;
		break;
	case 4:
		ret = ioreg_read32((__u32 *)NS8250_REG(reg));
		break;
	default:
		UK_CRASH("Invalid register width: %d\n", ns8250_reg_width);
	}

	ukplat_spin_unlock_irqrestore(&ns8250_lock, flags);

	return ret;
}

static inline void ns8250_reg_write(__u32 reg, __u32 value)
{
	int flags;

	ukplat_spin_lock_irqsave(&ns8250_lock, flags);

	switch (ns8250_reg_width) {
	case 1:
		ioreg_write8((__u8 *)NS8250_REG(reg),
			     (__u8)(value & 0xff));
		break;
	case 2:
		ioreg_write16((__u16 *)NS8250_REG(reg),
			      (__u16)(value & 0xffff));
		break;
	case 4:
		ioreg_write32((__u32 *)NS8250_REG(reg), value);
		break;
	default:
		UK_CRASH("Invalid register width: %d\n", ns8250_reg_width);
	}

	ukplat_spin_unlock_irqrestore(&ns8250_lock, flags);
}

static void ns8250_set_baudrate(__u16 divisor)
{
	/* Enable DLAB */
	ns8250_reg_write(NS8250_LCR_OFFSET,
					NS8250_LCR_DLAB | NS8250_LCR_8N1);
	/* Set divisor low byte */
	ns8250_reg_write(NS8250_DLL_OFFSET, divisor & 0xff);
	/* Set divisor high byte */
	ns8250_reg_write(NS8250_DLM_OFFSET, (divisor >> 8) & 0xff);
	/* Set the transceiver signal bit */
	ns8250_reg_write(NS8250_LCR_OFFSET, NS8250_LCR_8N1);
}

static void init_ns8250(__u64 base)
{
	__u16 ns8250_divisor = 0;

	ns8250_uart_base = base;
	ns8250_uart_initialized = 1;

	while (!(ns8250_reg_read(NS8250_LSR_OFFSET) & NS8250_LSR_TX_EMPTY))
		;

	if (ns8250_baudrate) {
		ns8250_divisor =
		(ns8250_uart_freq) / (ns8250_mode_x_div * ns8250_baudrate);
	}

	/* Disable all interrupts */
	ns8250_reg_write(NS8250_IER_OFFSET, 0x00);
	/* DTR RTS */
	ns8250_reg_write(NS8250_MCR_OFFSET, NS8250_MCR_SET);

	ns8250_reg_write(NS8250_FCR_OFFSET, NS8250_FCR_DEFVAL);
	/* Set baud rate */
	ns8250_set_baudrate(ns8250_divisor);

	uk_spin_init(&ns8250_lock);
}

void ns8250_console_init(const void *dtb)
{
	int offset, len, val;
	__u64 naddr, nsize, reg_uart_base;
	const __u64 *regs;
	__u32 default_ns8250_uart_freq = 24000000;

	if (unlikely((offset = fdt_path_offset_namelen(dtb,
		earlycon_node_name, strlen(earlycon_node_name))) < 0)) {
		UK_CRASH("No console UART found!\n");
	}

	val = fdt_get_address(dtb, offset, 0, &naddr, &nsize);
	if (val < 0)
		UK_CRASH("Could not find proper address!\n");

	reg_uart_base = naddr;

	regs = fdt_getprop(dtb, offset, "reg-shift", &len);
	if (regs)
		ns8250_reg_shift = EXTRACT_HIGH_BITS(*regs);

	regs = fdt_getprop(dtb, offset, "reg-io-width", &len);
	if (regs)
		ns8250_reg_width = EXTRACT_HIGH_BITS(*regs);

	if (fdt_getprop_u32_by_offset(dtb, offset, "clock-frequency",
			&ns8250_uart_freq)) {
		ns8250_uart_freq = default_ns8250_uart_freq;
		uk_pr_info("no freq in dtb, use default: 0x%x\n", ns8250_uart_freq);
	}

	init_ns8250(reg_uart_base);

	uk_pr_info("EARLYCON UART initialized\n");
}

int ukplat_coutd(const char *str, unsigned int len)
{
	return ukplat_coutk(str, len);
}

static void _putc(char a)
{
	/* Wait until TX FIFO becomes empty */
	while (!(ns8250_reg_read(NS8250_LSR_OFFSET) & NS8250_LSR_TX_EMPTY))
		;

	/* Reset DLAB and write to THR */
	ns8250_reg_write(NS8250_LCR_OFFSET,
			  ns8250_reg_read(NS8250_LCR_OFFSET) &
			  ~(NS8250_LCR_DLAB));
	ns8250_reg_write(NS8250_THR_OFFSET, a & 0xff);
}

static void ns8250_putc(char a)
{
	if (a == '\n')
		_putc('\r');
	_putc(a);
}

/* Try to get data from ns16550 UART without blocking */
static int ns8250_getc(void)
{
	/* If RX FIFO is empty, return -1 immediately */
	if (!(ns8250_reg_read(NS8250_LSR_OFFSET) & NS8250_LSR_RX_EMPTY))
		return -1;

	/* Reset DLAB and read from RBR */
	ns8250_reg_write(NS8250_LCR_OFFSET,
			  ns8250_reg_read(NS8250_LCR_OFFSET) &
			  ~(NS8250_LCR_DLAB));
	return (int)(ns8250_reg_read(NS8250_RBR_OFFSET) & 0xff);
}

int ukplat_coutk(const char *buf, unsigned int len)
{
	/*
	 * Avoid using the UART before base address initialized, or
	 * if CONFIG_LIBTNTTY_NS8250_EARLY_CONSOLE_BASE is not enabled.
	 */
	if (!ns8250_uart_initialized)
		return -1;

	for (unsigned int i = 0; i < len; i++)
		ns8250_putc(buf[i]);
	return len;
}

int ukplat_cink(char *buf, unsigned int maxlen)
{
	int ret;
	unsigned int num = 0;

	/*
	 * Avoid using the UART before base address initialized, or
	 * if CONFIG_LIBTNTTY_NS8250_EARLY_CONSOLE_BASE is not enabled.
	 */
	if (!ns8250_uart_initialized)
		return -1;

	while (num < maxlen && (ret = ns8250_getc()) >= 0) {
		*(buf++) = (char)ret;
		num++;
	}

	return (int)num;
}
