#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys

# Linux arm64 boot header
# https://www.kernel.org/doc/Documentation/arm64/booting.txt
LINUX_ARM64_HDR = {
    "CODE0"                   : (0x0000000091005a4d, 0x04),  # Offset   0
    "CODE1"                   : [0x0000000000000000, 0x04],  # Offset   4
    "LOAD_OFFS"               : [0x0000000000000000, 0x08],  # Offset   8
    "IMAGE_SIZE"              : [0x0000000000000000, 0x08],  # Offset  16
    "KERNEL_FLAGS"            : [0x0000000000000000, 0x08],  # Offset  24
    "RES2"                    : (0x0000000000000000, 0x08),  # Offset  32
    "RES3"                    : (0x0000000000000000, 0x08),  # Offset  40
    "RES4"                    : (0x0000000000000000, 0x08),  # Offset  48
    "MAGIC"                   : (0x00000000644d5241, 0x04),  # Offset  56
    "RES5"                    : (0x0000000000000040, 0x04),  # Offset  60
}
LINUX_ARM64_HDR_SIZE = 64

# surely there's a pythonic way for that
def align_up(v, a):
    return (((v) + (a)-1) & ~((a)-1))

def autoint(x):
    return int(x, 0)

# Get the absolute value of symbol, as seen through `nm`
def get_sym_val(elf, sym):
    exp = r'^\s*' + r'([a-f0-9]+)' + r'\s+[A-Za-z]\s+' + sym + r'$'
    out = subprocess.check_output(['nm', elf])

    re_out = re.findall(exp, out.decode('ASCII'), re.MULTILINE)
    if len(re_out) != 1:
        raise Exception('Found no ' + sym + ' symbol.')

    return int(re_out[0], 16)

def get_entry_point(elf_file):
    """
    Use the 'readelf -h' command to fetch the entry point address of a specified ELF file,
    and return it as an integer.

    Parameters:
    elf_file (str): Path to the ELF file.

    Returns:
    int: The entry point address as an integer if successfully retrieved, otherwise None.
    """
    try:
        # Execute the readelf command with '-h' to get the ELF file header information
        result = subprocess.run(['readelf', '-h', elf_file], env={"LANG":"C"}, text=True, capture_output=True, check=True)
        # Parse the output to find the entry point address
        for line in result.stdout.splitlines():
            if "Entry point address:" in line:
                # Extract the address and convert it from a hexadecimal string to an integer
                address_hex = line.split(":")[1].strip()
                return int(address_hex, 16)  # Convert the hexadecimal string to an integer
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except FileNotFoundError:
        print("Error: readelf is not installed or not found in PATH.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return None

def main():
    parser = argparse.ArgumentParser()
    description='Prepends image with arm64 linux boot header.'
    parser.add_argument('bin', help='Raw binary to prepend header with.')
    parser.add_argument('elf', help='The ELF image the raw binary was derived from. '
                        'Required for resolving symbols used in the header.')
    opt = parser.parse_args()

    ram_base = get_sym_val(opt.elf, r'_start_ram_addr')
    img_base = get_sym_val(opt.elf, r'_base_addr')
    entry = get_entry_point(opt.elf)

    # code1
    #
    # This contains an unconditional branch to the entry point.
    # The encoding of the branch instruction according to the
    # Arm ARM (DDI0487I.a) is:
    #
    # 31           25                            0
    # ┌───────────┬───────────────────────────────┐
    # │0 0 0 1 0 1│           imm26               │
    # └───────────┴───────────────────────────────┘
    #
    # b <offs>
    #
    # where offs is encoded as "imm26" times 4, relatively
    # to the branch instruction
    #
    pc = img_base - LINUX_ARM64_HDR_SIZE + 4
    offs = entry - pc

    # offset must be <= +128M. We don't accept negative offsets
    # here as the header always prepends the image.
    assert((offs) <= ((1 << 26) / 2 - 1))

    LINUX_ARM64_HDR["CODE1"][0] = ((0b101 << 26) | (int(offs / 4)))

    # load_offset
    #
    # This includes the header, so we subtract the header size
    LINUX_ARM64_HDR["LOAD_OFFS"][0] = (img_base - ram_base) - LINUX_ARM64_HDR_SIZE

    # kernel_flags
    #
    # For now assume little-endian, 4KiB pages, image anywhere in memory
    LINUX_ARM64_HDR["KERNEL_FLAGS"][0] = 0xa

    # image_size
    #
    # We arbitrarily set this to header size + image size aligned up to 2MiB
    total_size = os.path.getsize(opt.bin) + LINUX_ARM64_HDR_SIZE
    LINUX_ARM64_HDR["IMAGE_SIZE"][0] = align_up(total_size, 2 ** 21)

    # Create final image
    with open(opt.bin, 'r+b') as f:
        img = f.read()
        f.seek(0)
        for field in [k for k in LINUX_ARM64_HDR.keys()]:
            f.write(LINUX_ARM64_HDR[field][0].to_bytes(LINUX_ARM64_HDR[field][1], 'little'))
        f.write(img)

if __name__ == '__main__':
    main()
