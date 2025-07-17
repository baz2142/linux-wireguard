/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025 Nikita D. Bazulin <baz0x85e@gmail.com>. All Rights Reserved.
 */

#include "custom_signatures.h"

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>

static u64 calculate_base_numeric_hash(const char* data, size_t len)
{
    u64 hash_value = 0xABCD123456789ULL;

    for (size_t i = 0; i < len; ++i) {
        hash_value = (hash_value ^ (u64)data[i]) * 31ULL % 0xFFFFFFFFFFFFFFFFULL;
        hash_value += (u64)data[i];
    }

    return hash_value;
}

static char* generate_chained_hash(const char* input_string, size_t desired_length)
{
    if (input_string == NULL || desired_length == 0)
        return NULL;

    char* result_hash_str = kmalloc(desired_length + 1, GFP_KERNEL);

    if (result_hash_str == NULL)
    {
        pr_err("Failed to allocate memory for hash string\n");
        return NULL;
    }

    result_hash_str[0] = '\0';

    char current_hex_hash[17];
    const char* current_data_for_hashing = input_string;
    size_t current_data_len = strlen(input_string);
    size_t total_chars_generated = 0;

    while (total_chars_generated < desired_length) 
    {
        const unsigned long long numeric_hash = calculate_base_numeric_hash(current_data_for_hashing, current_data_len);
        
        snprintf(current_hex_hash, sizeof(current_hex_hash), "%llX", numeric_hash);

        const size_t part_len = strlen(current_hex_hash);
        size_t chars_to_copy = desired_length - total_chars_generated;

        if (chars_to_copy > part_len)
            chars_to_copy = part_len;

        strncat(result_hash_str, current_hex_hash, chars_to_copy);
        total_chars_generated += chars_to_copy;

        current_data_for_hashing = current_hex_hash;
        current_data_len = part_len;
    }
    
    result_hash_str[desired_length] = '\0';

    return result_hash_str;
}

static void parse_obfuscation_phrase_info_custom_signatures(u8* obfuscate_phrase, struct custom_signatures_t* custom_signatures)
{
    const size_t totalSize = sizeof(custom_signatures->cookie_key_label)
        + sizeof(custom_signatures->handshake_name)
        + sizeof(custom_signatures->identifier_name)
        + sizeof(custom_signatures->mac1_key_label)
        + sizeof(custom_signatures->wg_crypt)
        + sizeof(custom_signatures->wg_kex);

    const char* generated_hash_str = generate_chained_hash(obfuscate_phrase, totalSize);

    if (generated_hash_str == NULL)
    {
        pr_err("Failed to generate a hash of required length.\n");
        return;
    }

    pr_info("Generated hash (length %zu): %s\n", strlen(generated_hash_str), generated_hash_str);

    size_t current_hash_offset = 0;

    memcpy(custom_signatures->mac1_key_label, generated_hash_str + current_hash_offset, sizeof(custom_signatures->mac1_key_label));
    custom_signatures->mac1_key_label[sizeof(custom_signatures->mac1_key_label) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->mac1_key_label);

    memcpy(custom_signatures->cookie_key_label, generated_hash_str + current_hash_offset, sizeof(custom_signatures->cookie_key_label));
    custom_signatures->cookie_key_label[sizeof(custom_signatures->cookie_key_label) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->cookie_key_label);

    memcpy(custom_signatures->wg_kex, generated_hash_str + current_hash_offset, sizeof(custom_signatures->wg_kex));
    custom_signatures->wg_kex[sizeof(custom_signatures->wg_kex) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->wg_kex);

    memcpy(custom_signatures->wg_crypt, generated_hash_str + current_hash_offset, sizeof(custom_signatures->wg_crypt));
    custom_signatures->wg_crypt[sizeof(custom_signatures->wg_crypt) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->wg_crypt);

    memcpy(custom_signatures->handshake_name, generated_hash_str + current_hash_offset, sizeof(custom_signatures->handshake_name));
    custom_signatures->handshake_name[sizeof(custom_signatures->handshake_name) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->handshake_name);

    memcpy(custom_signatures->identifier_name, generated_hash_str + current_hash_offset, sizeof(custom_signatures->identifier_name));
    custom_signatures->identifier_name[sizeof(custom_signatures->identifier_name) - 1] = 0;
    current_hash_offset += sizeof(custom_signatures->identifier_name);

    kfree(generated_hash_str);
    generated_hash_str = NULL;
}

static struct custom_signatures_t* instance = NULL;

struct custom_signatures_t* custom_signatures_singleton(void)
{
    return instance;
}

void custom_signatures_print()
{
    pr_info("custom_signatures:");

    if (instance == NULL)
    {
        pr_info("custom_signatures: is NULL");
        return;
    }

    pr_info("cookie_key_label[%zu]: %s", strlen(instance->cookie_key_label), instance->cookie_key_label);
    pr_info("handshake_name[%zu]: %s", strlen(instance->handshake_name), instance->handshake_name);
    pr_info("identifier_name[%zu]: %s", strlen(instance->identifier_name), instance->identifier_name);
    pr_info("mac1_key_label[%zu]: %s", strlen(instance->mac1_key_label), instance->mac1_key_label);
    pr_info("wg_crypt[%zu]: %s", strlen(instance->wg_crypt), instance->wg_crypt);
    pr_info("wg_kex[%zu]: %s", strlen(instance->wg_kex), instance->wg_kex);
}

void custom_signatures_init(u8* obfuscate_phrase)
{
    instance = kmalloc(sizeof(struct custom_signatures_t), GFP_KERNEL);
    parse_obfuscation_phrase_info_custom_signatures(obfuscate_phrase, instance);
    pr_info("custom_signatures_singleton: Instance created.\n");
}

void custom_signatures_destructor(void)
{
    if (instance)
    {
        kfree(instance);
        instance = NULL;
        pr_info("custom_signatures_singleton: Instance destroyed.\n");
    }
}