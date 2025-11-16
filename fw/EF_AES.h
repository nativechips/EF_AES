/**
 * @file EF_AES.h
 * @brief AES-128/256 Hardware Accelerator Driver
 * @author Efabless Corporation
 * @version 1.0
 * @date 2025-11-16
 * 
 * @details
 * This driver provides a simple API for the EF_AES hardware accelerator.
 * Supports both 128-bit and 256-bit keys for encryption and decryption.
 * 
 * Features:
 * - AES-128 and AES-256 encryption/decryption
 * - Blocking and non-blocking operation modes
 * - Interrupt support
 * - Status checking utilities
 * 
 * Usage:
 *   1. Set the base address using AES_setBaseAddress()
 *   2. Call AES_encrypt_128() or AES_decrypt_256() etc.
 *   3. Wait for completion or use interrupts
 * 
 * @note All data buffers are little-endian 32-bit words
 */

#ifndef EF_AES_H
#define EF_AES_H

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Register Access Macros
// ============================================================================

#ifndef __R
#define __R volatile const  // Read-only
#endif

#ifndef __W
#define __W volatile        // Write-only
#endif

#ifndef __RW
#define __RW volatile       // Read-Write
#endif

// ============================================================================
// Register Offsets
// ============================================================================

#define EF_AES_STATUS_OFFSET        0x00
#define EF_AES_CTRL_OFFSET          0x04
#define EF_AES_KEY0_OFFSET          0x08
#define EF_AES_KEY1_OFFSET          0x0C
#define EF_AES_KEY2_OFFSET          0x10
#define EF_AES_KEY3_OFFSET          0x14
#define EF_AES_KEY4_OFFSET          0x18
#define EF_AES_KEY5_OFFSET          0x1C
#define EF_AES_KEY6_OFFSET          0x20
#define EF_AES_KEY7_OFFSET          0x24
#define EF_AES_BLOCK0_OFFSET        0x28
#define EF_AES_BLOCK1_OFFSET        0x2C
#define EF_AES_BLOCK2_OFFSET        0x30
#define EF_AES_BLOCK3_OFFSET        0x34
#define EF_AES_RESULT0_OFFSET       0x38
#define EF_AES_RESULT1_OFFSET       0x3C
#define EF_AES_RESULT2_OFFSET       0x40
#define EF_AES_RESULT3_OFFSET       0x44
#define EF_AES_IM_OFFSET            0xFF00
#define EF_AES_MIS_OFFSET           0xFF04
#define EF_AES_RIS_OFFSET           0xFF08
#define EF_AES_IC_OFFSET            0xFF0C

// ============================================================================
// Register Bit Definitions
// ============================================================================

// STATUS register (Read-Only)
#define EF_AES_STATUS_READY         (1 << 6)  // Key expansion complete
#define EF_AES_STATUS_VALID         (1 << 7)  // Result valid

// CTRL register (Write-Only)
#define EF_AES_CTRL_INIT            (1 << 0)  // Start key expansion
#define EF_AES_CTRL_NEXT            (1 << 1)  // Start encryption/decryption
#define EF_AES_CTRL_DECRYPT         (1 << 2)  // 0=encrypt, 1=decrypt
#define EF_AES_CTRL_KEY256          (1 << 3)  // 0=128-bit, 1=256-bit key

// Interrupt bits
#define EF_AES_IRQ_DONE             (1 << 0)  // Operation complete interrupt

// ============================================================================
// Data Types
// ============================================================================

/**
 * @brief AES key sizes
 */
typedef enum {
    AES_KEY_128 = 0,  // 128-bit key (4 words)
    AES_KEY_256 = 1   // 256-bit key (8 words)
} AES_KeySize_t;

/**
 * @brief AES operation mode
 */
typedef enum {
    AES_ENCRYPT = 0,  // Encryption mode
    AES_DECRYPT = 1   // Decryption mode
} AES_Mode_t;

/**
 * @brief AES return status codes
 */
typedef enum {
    AES_OK = 0,           // Operation successful
    AES_ERR_NULL_PTR,     // NULL pointer provided
    AES_ERR_TIMEOUT,      // Operation timeout
    AES_ERR_BUSY,         // AES core is busy
    AES_ERR_NOT_READY     // AES core not ready
} AES_Status_t;

// ============================================================================
// Global Base Address (must be set before using API)
// ============================================================================

extern uint32_t EF_AES_BASE_ADDR;

// ============================================================================
// Low-Level Register Access Functions
// ============================================================================

/**
 * @brief Set the base address for AES registers
 * @param base_addr Base address of AES peripheral
 */
void AES_setBaseAddress(uint32_t base_addr);

/**
 * @brief Write to AES register
 * @param offset Register offset
 * @param value Value to write
 */
void AES_writeReg(uint32_t offset, uint32_t value);

/**
 * @brief Read from AES register
 * @param offset Register offset
 * @return Register value
 */
uint32_t AES_readReg(uint32_t offset);

// ============================================================================
// Status Check Functions
// ============================================================================

/**
 * @brief Check if AES is ready (key expansion complete)
 * @return true if ready, false otherwise
 */
bool AES_isReady(void);

/**
 * @brief Check if result is valid
 * @return true if valid, false otherwise
 */
bool AES_isValid(void);

/**
 * @brief Wait for AES ready flag with timeout
 * @param timeout Maximum number of polling iterations (0 = infinite)
 * @return AES_OK if ready, AES_ERR_TIMEOUT if timeout
 */
AES_Status_t AES_waitReady(uint32_t timeout);

/**
 * @brief Wait for result valid flag with timeout
 * @param timeout Maximum number of polling iterations (0 = infinite)
 * @return AES_OK if valid, AES_ERR_TIMEOUT if timeout
 */
AES_Status_t AES_waitValid(uint32_t timeout);

// ============================================================================
// Key Management Functions
// ============================================================================

/**
 * @brief Load 128-bit key and perform key expansion
 * @param key Pointer to 4-word (16-byte) key array
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_loadKey128(const uint32_t key[4]);

/**
 * @brief Load 256-bit key and perform key expansion
 * @param key Pointer to 8-word (32-byte) key array
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_loadKey256(const uint32_t key[8]);

// ============================================================================
// High-Level Encryption/Decryption Functions (Blocking)
// ============================================================================

/**
 * @brief Encrypt 128-bit block with 128-bit key (blocking)
 * @param key Pointer to 4-word key
 * @param plaintext Pointer to 4-word plaintext
 * @param ciphertext Pointer to 4-word output buffer
 * @param timeout Timeout in iterations (0 = infinite)
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_encrypt128(const uint32_t key[4], 
                             const uint32_t plaintext[4],
                             uint32_t ciphertext[4],
                             uint32_t timeout);

/**
 * @brief Decrypt 128-bit block with 128-bit key (blocking)
 * @param key Pointer to 4-word key
 * @param ciphertext Pointer to 4-word ciphertext
 * @param plaintext Pointer to 4-word output buffer
 * @param timeout Timeout in iterations (0 = infinite)
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_decrypt128(const uint32_t key[4],
                             const uint32_t ciphertext[4],
                             uint32_t plaintext[4],
                             uint32_t timeout);

/**
 * @brief Encrypt 128-bit block with 256-bit key (blocking)
 * @param key Pointer to 8-word key
 * @param plaintext Pointer to 4-word plaintext
 * @param ciphertext Pointer to 4-word output buffer
 * @param timeout Timeout in iterations (0 = infinite)
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_encrypt256(const uint32_t key[8],
                             const uint32_t plaintext[4],
                             uint32_t ciphertext[4],
                             uint32_t timeout);

/**
 * @brief Decrypt 128-bit block with 256-bit key (blocking)
 * @param key Pointer to 8-word key
 * @param ciphertext Pointer to 4-word ciphertext
 * @param plaintext Pointer to 4-word output buffer
 * @param timeout Timeout in iterations (0 = infinite)
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_decrypt256(const uint32_t key[8],
                             const uint32_t ciphertext[4],
                             uint32_t plaintext[4],
                             uint32_t timeout);

// ============================================================================
// Advanced Non-Blocking Functions
// ============================================================================

/**
 * @brief Start encryption/decryption operation (non-blocking)
 * @param plaintext Pointer to 4-word input block
 * @param mode AES_ENCRYPT or AES_DECRYPT
 * @return AES_OK on success, error code otherwise
 * @note Key must already be loaded with AES_loadKey128/256
 */
AES_Status_t AES_startOperation(const uint32_t block[4], AES_Mode_t mode);

/**
 * @brief Read result from AES (non-blocking)
 * @param result Pointer to 4-word output buffer
 * @return AES_OK on success, error code otherwise
 */
AES_Status_t AES_readResult(uint32_t result[4]);

// ============================================================================
// Interrupt Management Functions
// ============================================================================

/**
 * @brief Enable AES interrupt
 */
void AES_enableInterrupt(void);

/**
 * @brief Disable AES interrupt
 */
void AES_disableInterrupt(void);

/**
 * @brief Check raw interrupt status
 * @return true if interrupt pending, false otherwise
 */
bool AES_getInterruptStatus(void);

/**
 * @brief Clear AES interrupt
 */
void AES_clearInterrupt(void);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Convert byte array to word array (little-endian)
 * @param bytes Input byte array
 * @param words Output word array
 * @param num_words Number of words to convert
 */
void AES_bytesToWords(const uint8_t *bytes, uint32_t *words, uint32_t num_words);

/**
 * @brief Convert word array to byte array (little-endian)
 * @param words Input word array
 * @param bytes Output byte array
 * @param num_words Number of words to convert
 */
void AES_wordsToBytes(const uint32_t *words, uint8_t *bytes, uint32_t num_words);

#endif // EF_AES_H
