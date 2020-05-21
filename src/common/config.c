/*
 * Copyright (C) 2020 Evan Lojewski
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <board/flash.h>
#include <common/config.h>
#include <common/debug.h>
#include <stddef.h>
#include <string.h>

// Prevent failures to compile on AVR
#ifndef __SDCC
    #define __code
#endif

config_t *g_config_entries = NULL;

#define CONFIG_ADDRESS  (0x10000L)
#define CONFIG_SIZE   (1 * 1024)  /* 1K block - code currently assumes this matches the erase size */
#define CONFIG_PERSISTANT_MAGIC     (0xCF1C0F10)

uint32_t __code __at(CONFIG_ADDRESS) config_magic;
uint8_t __code __at(CONFIG_ADDRESS + sizeof(config_magic)) config_persistant[CONFIG_SIZE - sizeof(config_magic)];

#define CONFIG_FLASH_ENTRY_LENGTH_INVALID   (0xFF)
#define CONFIG_FLASH_ENTRY_CURRENT          (0xFF)
#define CONFIG_FLASH_ENTRY_OBSOLETE         (0x00)

#define CONFIG_FLASH_ENTRY_CURRENT_OFFSET   (0)
#define CONFIG_FLASH_ENTRY_LEN_OFFSET       (1)
#define CONFIG_FLASH_ENTRY_VALUE_OFFSET     (2)
#define CONFIG_FLASH_ENTRY_NAME_OFFSET      (6)
#define CONFIG_FLASH_ENTRY_HEADER_SIZE      (6)
// config_persistant format
// (1) byte: Current / Obsolete. When a config entry is updated, byte is written to Obsolete and a new entry is added later.
// (1) byte: Short Name Length. When 0xFF, no more config entries exist.
// (4) bytes: Value
// Len Bytes: short name.

int8_t flash_strncmp(uint32_t addr, const char* str, uint8_t len) {
    while(len) {
        char byte = flash_read_u8(addr);

        char res = *str - byte;
        if(res) {
            return res;
        }
        len--;
        addr++;
        str++;
    }

    return 0;
}


bool config_validate_magic(void) {
    uint32_t magic = flash_read_u32(CONFIG_ADDRESS);

    return (CONFIG_PERSISTANT_MAGIC == magic);
}

uint32_t config_find_free_entry() {
    if (!config_validate_magic()) {
        // Write magic.
        flash_write_u32(CONFIG_ADDRESS, CONFIG_PERSISTANT_MAGIC);
    }

    uint32_t addr = CONFIG_ADDRESS + sizeof(config_magic);
    uint32_t limit = addr + sizeof(config_persistant);
    while(addr < limit) {
        // configuration present.
        uint8_t len;
        len = flash_read_u8(addr + CONFIG_FLASH_ENTRY_LEN_OFFSET);

        if(CONFIG_FLASH_ENTRY_LENGTH_INVALID == len) {
            // Free entry found.
            return addr;
        }

        // Go to the next entry.
        addr += CONFIG_FLASH_ENTRY_NAME_OFFSET + len;
    }

    return 0;
}

void config_save_entry_len(uint32_t addr, uint8_t len) {
    flash_write_u8(addr + CONFIG_FLASH_ENTRY_LEN_OFFSET, len);
}

void config_save_entry_value(uint32_t addr, int32_t value) {
    flash_write_u32(addr + CONFIG_FLASH_ENTRY_VALUE_OFFSET, value);
}

bool config_save_entry(const char* config_short, int32_t value) {
    uint32_t addr = config_find_free_entry();
    uint8_t len = strlen(config_short);
    uint32_t needed_space = len + CONFIG_FLASH_ENTRY_HEADER_SIZE;


    if (addr && ((addr + needed_space - CONFIG_ADDRESS) < sizeof(config_persistant))) {
        DEBUG("Saving config: %s", config_short);
        DEBUG(" = %ld\n", value);

        config_save_entry_len(addr, len);

        config_save_entry_value(addr, value);

        // Flash write only allows pointers in __xdata, enforce this.
        while (len) {
            len--;
            flash_write_u8(addr + CONFIG_FLASH_ENTRY_NAME_OFFSET + len, config_short[len]);
        }

        return true;
    } else {
        return false;
    }
}

void config_save_entries() __reentrant {
    config_t *entry = g_config_entries;

    while (entry) {
        (void)config_save_entry(entry->config_short, entry->value.value);
        entry = entry->next;
    }
}

bool config_flash_found(uint32_t addr, const char* config_short, uint8_t len) {
    return (0 == flash_strncmp(addr + CONFIG_FLASH_ENTRY_NAME_OFFSET, config_short, len));
}

bool config_flash_valid(uint32_t addr) {
    return (CONFIG_FLASH_ENTRY_CURRENT == flash_read_u8(addr + CONFIG_FLASH_ENTRY_CURRENT_OFFSET));
}

uint8_t config_flash_len(uint32_t addr) {
    return flash_read_u8(addr + CONFIG_FLASH_ENTRY_LEN_OFFSET);
}

int32_t config_flash_value(uint32_t addr) {
    return flash_read_u32(addr + CONFIG_FLASH_ENTRY_VALUE_OFFSET);
}

uint32_t condif_flash_next(uint32_t addr) {
    uint8_t len = config_flash_len(addr);
    return addr + CONFIG_FLASH_ENTRY_NAME_OFFSET + len;
}

uint32_t config_find_entry(const char* config_short) {
    if(config_validate_magic()) {
        uint32_t addr = CONFIG_ADDRESS + sizeof(config_magic);
        uint32_t limit = addr + sizeof(config_persistant);

        while(addr < limit) {
            uint8_t len;
            // configuration present.
            len = config_flash_len(addr);

            if(CONFIG_FLASH_ENTRY_LENGTH_INVALID == len) {
                // no more entries exist.
                break;
            }

            if(config_flash_valid(addr)) {
                if(config_flash_found(addr, config_short, len)) {
                    return addr;
                }
            }

            // Go to the next entry.
            addr = condif_flash_next(addr);
        }
    }

    // Not found.
    return 0;
}

void config_invalidate_entry(uint32_t addr) {
    if (addr) {
        flash_write_u8(addr + CONFIG_FLASH_ENTRY_CURRENT_OFFSET, CONFIG_FLASH_ENTRY_OBSOLETE);
    }
}

bool config_register(config_t *entry) __reentrant {
    // Validate entry parameters.
    if (!entry) {
        return false;
    }

    // Short name and desc must be set.
    if (!entry->config_short || !entry->config_desc) {
        return false;
    }

    // Config validated, register it
    entry->next = g_config_entries;
    g_config_entries = entry;

    // Read the stored value from flash, if present.
    uint32_t flash_addr = config_find_entry(entry->config_short);
    if (flash_addr) {
        int32_t saved_value = config_flash_value(flash_addr);

        int64_t min = entry->value.min_value;
        int64_t max = entry->value.max_value;

        if (min <= saved_value &&
            max >= saved_value) {
            entry->value.value = saved_value;

            /* Notify any listeners. */
            if (entry->set_callback) {
                entry->set_callback(entry);
            }
        }
    }


    return true;
}

config_t *config_get_config(const char *config_short) {
    config_t *current = g_config_entries;

    while (current && 0 != strcmp(current->config_short, config_short)) {
        current = current->next;
    }

    return current;
}

config_t *config_next(config_t *current) {
    if (current) {
        current = current->next;
    }

    return current;
}

config_t *config_index(int32_t index) {
    config_t *current = g_config_entries;

    while (current && index) {
        current = current->next;
        index = index - 1;
    }

    return current;
}

int32_t config_get_value(config_t *config) __reentrant {
    if (config) {
        return config->value.value;
    }
    else {
        // Invalid
        return 0;
    }

}

bool config_set_value(config_t *config, int32_t value) __reentrant {
    bool valid = false;

    if (config) {
        bool saved = true;
        int64_t min = config->value.min_value;
        int64_t max = config->value.max_value;

        if (min <= value &&
            max >= value) {
            config->value.value = value;
            valid = true;

            /* Save the new value to flash, if it's changed */
            uint32_t flash_addr = config_find_entry(config->config_short);

            if (flash_addr) {
                int32_t oldval = config_flash_value(flash_addr);

                if(oldval != value) {
                    config_invalidate_entry(flash_addr);
                    saved = config_save_entry(config->config_short, value);
                }
            } else {
                // No entry, create one.
                saved = config_save_entry(config->config_short, value);
            }

            /* Notify any listeners. */
            if (config->set_callback) {
                config->set_callback(config);
            }
        }

        if (!saved) {
            // Not enough space exists. clear out flash and re-write.
            flash_erase(CONFIG_ADDRESS);

            config_save_entries();

        }
    }

    return valid;
}
