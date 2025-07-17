/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025 Nikita D. Bazulin <baz0x85e@gmail.com>. All Rights Reserved.
 */

#ifndef _WG_CUSTOM_SIGNATURES_H
#define _WG_CUSTOM_SIGNATURES_H

#include <linux/types.h>

enum { COOKIE_KEY_LABEL_LEN = 8 };

struct custom_signatures_t
{
    u8 mac1_key_label[COOKIE_KEY_LABEL_LEN + 1];
    u8 cookie_key_label[COOKIE_KEY_LABEL_LEN + 1];
    u8 wg_kex[6+1];
    u8 wg_crypt[8+1];
    u8 handshake_name[37+1];
    u8 identifier_name[34+1];
};

struct custom_signatures_t* custom_signatures_singleton(void);

void custom_signatures_print(void);
void custom_signatures_init(u8* obfuscate_phrase);
void custom_signatures_destructor(void);

#endif /* _WG_CUSTOM_SIGNATURES_H */