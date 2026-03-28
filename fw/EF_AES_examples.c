/**
 * @file EF_AES_examples.c
 * @brief Example usage of EF_AES driver API
 * @author Efabless Corporation
 * @version 1.0
 * @date 2025-11-16
 */

#include "EF_AES.h"
#include <stdio.h>

// ============================================================================
// Example 1: Simple AES-128 Encryption
// ============================================================================

void example_simple_aes128_encrypt(void) {
    printf("\n=== Example 1: Simple AES-128 Encryption ===\n");
    
    // Set base address (for Caravel user project area)
    AES_setBaseAddress(0x30000000);
    
    // Test vectors (all zeros)
    uint32_t key[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t plaintext[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t ciphertext[4];
    
    // Encrypt
    AES_Status_t status = AES_encrypt128(key, plaintext, ciphertext, 0);
    
    if (status == AES_OK) {
        printf("Encryption successful!\n");
        printf("Ciphertext: %08X %08X %08X %08X\n", 
               ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
    } else {
        printf("Encryption failed with error: %d\n", status);
    }
}

// ============================================================================
// Example 2: AES-128 Encrypt and Decrypt
// ============================================================================

void example_aes128_encrypt_decrypt(void) {
    printf("\n=== Example 2: AES-128 Encrypt and Decrypt ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    // Original data
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    uint32_t plaintext[4] = {0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734};
    uint32_t ciphertext[4];
    uint32_t decrypted[4];
    
    // Encrypt
    printf("Original plaintext: %08X %08X %08X %08X\n",
           plaintext[0], plaintext[1], plaintext[2], plaintext[3]);
    
    AES_Status_t status = AES_encrypt128(key, plaintext, ciphertext, 0);
    if (status != AES_OK) {
        printf("Encryption failed!\n");
        return;
    }
    
    printf("Ciphertext:         %08X %08X %08X %08X\n",
           ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
    
    // Decrypt
    status = AES_decrypt128(key, ciphertext, decrypted, 0);
    if (status != AES_OK) {
        printf("Decryption failed!\n");
        return;
    }
    
    printf("Decrypted plaintext: %08X %08X %08X %08X\n",
           decrypted[0], decrypted[1], decrypted[2], decrypted[3]);
    
    // Verify
    if (plaintext[0] == decrypted[0] && plaintext[1] == decrypted[1] &&
        plaintext[2] == decrypted[2] && plaintext[3] == decrypted[3]) {
        printf("SUCCESS: Decryption matches original plaintext!\n");
    } else {
        printf("ERROR: Decryption does not match!\n");
    }
}

// ============================================================================
// Example 3: AES-256 Encryption
// ============================================================================

void example_aes256_encrypt(void) {
    printf("\n=== Example 3: AES-256 Encryption ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    // 256-bit key (8 words)
    uint32_t key[8] = {
        0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
        0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4
    };
    
    uint32_t plaintext[4] = {0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a};
    uint32_t ciphertext[4];
    
    // Encrypt with 256-bit key
    AES_Status_t status = AES_encrypt256(key, plaintext, ciphertext, 0);
    
    if (status == AES_OK) {
        printf("AES-256 Encryption successful!\n");
        printf("Ciphertext: %08X %08X %08X %08X\n",
               ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
    } else {
        printf("Encryption failed with error: %d\n", status);
    }
}

// ============================================================================
// Example 4: Non-Blocking Operation with Interrupt
// ============================================================================

volatile bool aes_done = false;

void aes_interrupt_handler(void) {
    if (AES_getInterruptStatus()) {
        AES_clearInterrupt();
        aes_done = true;
    }
}

void example_nonblocking_with_interrupt(void) {
    printf("\n=== Example 4: Non-Blocking with Interrupt ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    // Test data
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    uint32_t plaintext[4] = {0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734};
    uint32_t ciphertext[4];
    
    // Load key (blocking)
    AES_Status_t status = AES_loadKey128(key);
    if (status != AES_OK) {
        printf("Key loading failed!\n");
        return;
    }
    
    // Enable interrupt
    AES_enableInterrupt();
    aes_done = false;
    
    // Start encryption (non-blocking)
    status = AES_startOperation(plaintext, AES_ENCRYPT);
    if (status != AES_OK) {
        printf("Operation start failed!\n");
        return;
    }
    
    printf("Encryption started, waiting for interrupt...\n");
    
    // Wait for interrupt (in real application, do other work here)
    while (!aes_done) {
        // Could do other work here
    }
    
    // Read result
    status = AES_readResult(ciphertext);
    if (status == AES_OK) {
        printf("Encryption completed!\n");
        printf("Ciphertext: %08X %08X %08X %08X\n",
               ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
    }
    
    // Disable interrupt
    AES_disableInterrupt();
}

// ============================================================================
// Example 5: Using Byte Arrays Instead of Words
// ============================================================================

void example_byte_array_encryption(void) {
    printf("\n=== Example 5: Byte Array Encryption ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    // Key and plaintext as byte arrays
    uint8_t key_bytes[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext_bytes[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    // Convert to words
    uint32_t key[4];
    uint32_t plaintext[4];
    uint32_t ciphertext[4];
    uint8_t ciphertext_bytes[16];
    
    AES_bytesToWords(key_bytes, key, 4);
    AES_bytesToWords(plaintext_bytes, plaintext, 4);
    
    // Encrypt
    AES_Status_t status = AES_encrypt128(key, plaintext, ciphertext, 0);
    if (status != AES_OK) {
        printf("Encryption failed!\n");
        return;
    }
    
    // Convert result back to bytes
    AES_wordsToBytes(ciphertext, ciphertext_bytes, 4);
    
    printf("Ciphertext (bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", ciphertext_bytes[i]);
    }
    printf("\n");
}

// ============================================================================
// Example 6: Multiple Block Encryption (Simple ECB Mode)
// ============================================================================

void example_multi_block_encryption(void) {
    printf("\n=== Example 6: Multiple Block Encryption ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    
    // Multiple blocks to encrypt
    uint32_t plaintext_blocks[3][4] = {
        {0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a},
        {0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51},
        {0x30c81c46, 0xa35ce411, 0xe5fbc119, 0x1a0a52ef}
    };
    
    uint32_t ciphertext_blocks[3][4];
    
    // Load key once (blocks will be faster since key is already loaded)
    AES_Status_t status = AES_loadKey128(key);
    if (status != AES_OK) {
        printf("Key loading failed!\n");
        return;
    }
    
    printf("Encrypting 3 blocks...\n");
    
    // Encrypt each block
    for (int i = 0; i < 3; i++) {
        status = AES_startOperation(plaintext_blocks[i], AES_ENCRYPT);
        if (status != AES_OK) {
            printf("Block %d: Start failed!\n", i);
            continue;
        }
        
        status = AES_waitValid(100000);
        if (status != AES_OK) {
            printf("Block %d: Wait failed!\n", i);
            continue;
        }
        
        status = AES_readResult(ciphertext_blocks[i]);
        if (status == AES_OK) {
            printf("Block %d: %08X %08X %08X %08X\n", i,
                   ciphertext_blocks[i][0], ciphertext_blocks[i][1],
                   ciphertext_blocks[i][2], ciphertext_blocks[i][3]);
        }
    }
}

// ============================================================================
// Example 7: Error Handling
// ============================================================================

void example_error_handling(void) {
    printf("\n=== Example 7: Error Handling ===\n");
    
    // Set base address
    AES_setBaseAddress(0x30000000);
    
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    uint32_t plaintext[4] = {0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734};
    uint32_t ciphertext[4];
    
    // Test NULL pointer handling
    AES_Status_t status = AES_encrypt128(NULL, plaintext, ciphertext, 0);
    if (status == AES_ERR_NULL_PTR) {
        printf("Correctly caught NULL pointer error\n");
    }
    
    // Test timeout handling (very short timeout will fail)
    status = AES_encrypt128(key, plaintext, ciphertext, 1);
    if (status == AES_ERR_TIMEOUT) {
        printf("Correctly caught timeout error\n");
    } else if (status == AES_OK) {
        printf("Operation completed (timeout was sufficient)\n");
    }
    
    // Proper operation with reasonable timeout
    status = AES_encrypt128(key, plaintext, ciphertext, 1000000);
    if (status == AES_OK) {
        printf("Operation successful with proper timeout\n");
    }
}

// ============================================================================
// Main Function (calls all examples)
// ============================================================================

#ifdef STANDALONE_EXAMPLES
int main(void) {
    printf("EF_AES Driver API Examples\n");
    printf("===========================\n");
    
    example_simple_aes128_encrypt();
    example_aes128_encrypt_decrypt();
    example_aes256_encrypt();
    example_byte_array_encryption();
    example_multi_block_encryption();
    example_error_handling();
    
    // Note: Interrupt example requires interrupt setup
    // example_nonblocking_with_interrupt();
    
    printf("\nAll examples completed!\n");
    return 0;
}
#endif
