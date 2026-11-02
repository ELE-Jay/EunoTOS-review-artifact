/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021 OpenSynergy GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __UK_TTY_PL011_H__
#define __UK_TTY_PL011_H__

#ifdef __cplusplus
extern "C" {
#endif

/* PL011 UART registers and masks*/
/* Data register */
#define REG_UARTDR_OFFSET	0x00

/* Receive status register/error clear register */
#define REG_UARTRSR_OFFSET	0x04
#define REG_UARTECR_OFFSET	0x04

/* Flag register */
#define REG_UARTFR_OFFSET	0x18
#define FR_TXFF			(1 << 5)    /* Transmit FIFO/reg full */
#define FR_RXFE			(1 << 4)    /* Receive FIFO/reg empty */

/* Integer baud rate register */
#define REG_UARTIBRD_OFFSET	0x24
/* Fractional baud rate register */
#define REG_UARTFBRD_OFFSET	0x28

/* Line control register */
#define REG_UARTLCR_H_OFFSET	0x2C
#define LCR_H_WLEN8		(0x3 << 5)  /* Data width is 8-bits */

/* Control register */
#define REG_UARTCR_OFFSET	0x30
#define CR_RXE			(1 << 9)    /* Receive enable */
#define CR_TXE			(1 << 8)    /* Transmit enable */
#define CR_UARTEN		(1 << 0)    /* UART enable */

/* Interrupt FIFO level select register */
#define REG_UARTIFLS_OFFSET	0x34
/* Interrupt mask set/clear register */
#define REG_UARTIMSC_OFFSET	0x38
/* Raw interrupt status register */
#define REG_UARTRIS_OFFSET	0x3C
/* Masked interrupt status register */
#define REG_UARTMIS_OFFSET	0x40
/* Interrupt clear register */
#define REG_UARTICR_OFFSET	0x44

extern uint8_t pl011_uart_initialized;
extern uint64_t pl011_uart_bas;

/* Macros to access PL011 Registers with base address */
#define PL011_REG(r)		((uint16_t *)(pl011_uart_bas + (r)))
#define PL011_REG_READ(r)	ioreg_read16(PL011_REG(r))
#define PL011_REG_WRITE(r, v)	ioreg_write16(PL011_REG(r), v)

/**
 * Initialize the pl011 console driver
 */
void pl011_console_init(const void *dtb);

#ifdef __cplusplus
}
#endif

#endif /* __UK_TTY_PL011_H__ */
