/**
 * @file EF_AES.c
 * @brief AES-128/256 Hardware Accelerator Driver Implementation
 * @author Efabless Corporation
 * @version 1.0
 * @date 2025-11-16
 */

#include <stddef.h>
#include "EF_AES.h"

// ============================================================================
// Global Variables
// ============================================================================

uint32_t EF_AES_BASE_ADDR = 0x00000000;  // Must be set by user

// ============================================================================
// Low-Level Register Access Functions
// ============================================================================

void AES_setBaseAddress(uint32_t base_addr) {
    EF_AES_BASE_ADDR = base_addr;
}

void AES_writeReg(uint32_t offset, uint32_t value) {
    *((volatile uint32_t*)(EF_AES_BASE_ADDR + offset)) = value;
}

uint32_t AES_readReg(uint32_t offset) {
    return *((volatile uint32_t*)(EF_AES_BASE_ADDR + offset));
}

// ============================================================================
// Status Check Functions
// ============================================================================

bool AES_isReady(void) {
    uint32_t status = AES_readReg(EF_AES_STATUS_OFFSET);
    return (status & EF_AES_STATUS_READY) != 0;
}

bool AES_isValid(void) {
    uint32_t status = AES_readReg(EF_AES_STATUS_OFFSET);
    return (status & EF_AES_STATUS_VALID) != 0;
}

AES_Status_t AES_waitReady(uint32_t timeout) {
    uint32_t count = 0;
    
    while (!AES_isReady()) {
        if (timeout > 0) {
            count++;
            if (count >= timeout) {
                return AES_ERR_TIMEOUT;
            }
        }
    }
    
    return AES_OK;
}

AES_Status_t AES_waitValid(uint32_t timeout) {
    uint32_t count = 0;
    
    while (!AES_isValid()) {
        if (timeout > 0) {
            count++;
            if (count >= timeout) {
                return AES_ERR_TIMEOUT;
            }
        }
    }
    
    return AES_OK;
}

// ============================================================================
// Key Management Functions
// ============================================================================

AES_Status_t AES_loadKey128(const uint32_t key[4]) {
    if (key == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Load 128-bit key (4 words)
    AES_writeReg(EF_AES_KEY0_OFFSET, key[0]);
    AES_writeReg(EF_AES_KEY1_OFFSET, key[1]);
    AES_writeReg(EF_AES_KEY2_OFFSET, key[2]);
    AES_writeReg(EF_AES_KEY3_OFFSET, key[3]);
    
    // Start key expansion (INIT=1, KEYLEN=0 for 128-bit)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_INIT);
    
    // Wait for key expansion to complete
    return AES_waitReady(100000);
}

AES_Status_t AES_loadKey256(const uint32_t key[8]) {
    if (key == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Load 256-bit key (8 words)
    AES_writeReg(EF_AES_KEY0_OFFSET, key[0]);
    AES_writeReg(EF_AES_KEY1_OFFSET, key[1]);
    AES_writeReg(EF_AES_KEY2_OFFSET, key[2]);
    AES_writeReg(EF_AES_KEY3_OFFSET, key[3]);
    AES_writeReg(EF_AES_KEY4_OFFSET, key[4]);
    AES_writeReg(EF_AES_KEY5_OFFSET, key[5]);
    AES_writeReg(EF_AES_KEY6_OFFSET, key[6]);
    AES_writeReg(EF_AES_KEY7_OFFSET, key[7]);
    
    // Start key expansion (INIT=1, KEYLEN=1 for 256-bit)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_INIT | EF_AES_CTRL_KEY256);
    
    // Wait for key expansion to complete
    return AES_waitReady(100000);
}

// ============================================================================
// High-Level Encryption/Decryption Functions
// ============================================================================

AES_Status_t AES_encrypt128(const uint32_t key[4], 
                             const uint32_t plaintext[4],
                             uint32_t ciphertext[4],
                             uint32_t timeout) {
    AES_Status_t status;
    
    // Validate pointers
    if (key == NULL || plaintext == NULL || ciphertext == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Set timeout to reasonable default if 0
    if (timeout == 0) {
        timeout = 1000000;
    }
    
    // Load key and wait for expansion
    status = AES_loadKey128(key);
    if (status != AES_OK) {
        return status;
    }
    
    // Load plaintext block
    AES_writeReg(EF_AES_BLOCK0_OFFSET, plaintext[0]);
    AES_writeReg(EF_AES_BLOCK1_OFFSET, plaintext[1]);
    AES_writeReg(EF_AES_BLOCK2_OFFSET, plaintext[2]);
    AES_writeReg(EF_AES_BLOCK3_OFFSET, plaintext[3]);
    
    // Start encryption (NEXT=1, ENCDEC=0)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_NEXT);
    
    // Wait for completion
    status = AES_waitValid(timeout);
    if (status != AES_OK) {
        return status;
    }
    
    // Read result
    ciphertext[0] = AES_readReg(EF_AES_RESULT0_OFFSET);
    ciphertext[1] = AES_readReg(EF_AES_RESULT1_OFFSET);
    ciphertext[2] = AES_readReg(EF_AES_RESULT2_OFFSET);
    ciphertext[3] = AES_readReg(EF_AES_RESULT3_OFFSET);
    
    return AES_OK;
}

AES_Status_t AES_decrypt128(const uint32_t key[4],
                             const uint32_t ciphertext[4],
                             uint32_t plaintext[4],
                             uint32_t timeout) {
    AES_Status_t status;
    
    // Validate pointers
    if (key == NULL || ciphertext == NULL || plaintext == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Set timeout to reasonable default if 0
    if (timeout == 0) {
        timeout = 1000000;
    }
    
    // Load key and wait for expansion
    status = AES_loadKey128(key);
    if (status != AES_OK) {
        return status;
    }
    
    // Load ciphertext block
    AES_writeReg(EF_AES_BLOCK0_OFFSET, ciphertext[0]);
    AES_writeReg(EF_AES_BLOCK1_OFFSET, ciphertext[1]);
    AES_writeReg(EF_AES_BLOCK2_OFFSET, ciphertext[2]);
    AES_writeReg(EF_AES_BLOCK3_OFFSET, ciphertext[3]);
    
    // Start decryption (NEXT=1, ENCDEC=1)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_NEXT | EF_AES_CTRL_DECRYPT);
    
    // Wait for completion
    status = AES_waitValid(timeout);
    if (status != AES_OK) {
        return status;
    }
    
    // Read result
    plaintext[0] = AES_readReg(EF_AES_RESULT0_OFFSET);
    plaintext[1] = AES_readReg(EF_AES_RESULT1_OFFSET);
    plaintext[2] = AES_readReg(EF_AES_RESULT2_OFFSET);
    plaintext[3] = AES_readReg(EF_AES_RESULT3_OFFSET);
    
    return AES_OK;
}

AES_Status_t AES_encrypt256(const uint32_t key[8],
                             const uint32_t plaintext[4],
                             uint32_t ciphertext[4],
                             uint32_t timeout) {
    AES_Status_t status;
    
    // Validate pointers
    if (key == NULL || plaintext == NULL || ciphertext == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Set timeout to reasonable default if 0
    if (timeout == 0) {
        timeout = 1000000;
    }
    
    // Load key and wait for expansion
    status = AES_loadKey256(key);
    if (status != AES_OK) {
        return status;
    }
    
    // Load plaintext block
    AES_writeReg(EF_AES_BLOCK0_OFFSET, plaintext[0]);
    AES_writeReg(EF_AES_BLOCK1_OFFSET, plaintext[1]);
    AES_writeReg(EF_AES_BLOCK2_OFFSET, plaintext[2]);
    AES_writeReg(EF_AES_BLOCK3_OFFSET, plaintext[3]);
    
    // Start encryption (NEXT=1, ENCDEC=0)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_NEXT);
    
    // Wait for completion
    status = AES_waitValid(timeout);
    if (status != AES_OK) {
        return status;
    }
    
    // Read result
    ciphertext[0] = AES_readReg(EF_AES_RESULT0_OFFSET);
    ciphertext[1] = AES_readReg(EF_AES_RESULT1_OFFSET);
    ciphertext[2] = AES_readReg(EF_AES_RESULT2_OFFSET);
    ciphertext[3] = AES_readReg(EF_AES_RESULT3_OFFSET);
    
    return AES_OK;
}

AES_Status_t AES_decrypt256(const uint32_t key[8],
                             const uint32_t ciphertext[4],
                             uint32_t plaintext[4],
                             uint32_t timeout) {
    AES_Status_t status;
    
    // Validate pointers
    if (key == NULL || ciphertext == NULL || plaintext == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Set timeout to reasonable default if 0
    if (timeout == 0) {
        timeout = 1000000;
    }
    
    // Load key and wait for expansion
    status = AES_loadKey256(key);
    if (status != AES_OK) {
        return status;
    }
    
    // Load ciphertext block
    AES_writeReg(EF_AES_BLOCK0_OFFSET, ciphertext[0]);
    AES_writeReg(EF_AES_BLOCK1_OFFSET, ciphertext[1]);
    AES_writeReg(EF_AES_BLOCK2_OFFSET, ciphertext[2]);
    AES_writeReg(EF_AES_BLOCK3_OFFSET, ciphertext[3]);
    
    // Start decryption (NEXT=1, ENCDEC=1)
    AES_writeReg(EF_AES_CTRL_OFFSET, EF_AES_CTRL_NEXT | EF_AES_CTRL_DECRYPT);
    
    // Wait for completion
    status = AES_waitValid(timeout);
    if (status != AES_OK) {
        return status;
    }
    
    // Read result
    plaintext[0] = AES_readReg(EF_AES_RESULT0_OFFSET);
    plaintext[1] = AES_readReg(EF_AES_RESULT1_OFFSET);
    plaintext[2] = AES_readReg(EF_AES_RESULT2_OFFSET);
    plaintext[3] = AES_readReg(EF_AES_RESULT3_OFFSET);
    
    return AES_OK;
}

// ============================================================================
// Advanced Non-Blocking Functions
// ============================================================================

AES_Status_t AES_startOperation(const uint32_t block[4], AES_Mode_t mode) {
    if (block == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Check if AES is ready
    if (!AES_isReady()) {
        return AES_ERR_NOT_READY;
    }
    
    // Load block
    AES_writeReg(EF_AES_BLOCK0_OFFSET, block[0]);
    AES_writeReg(EF_AES_BLOCK1_OFFSET, block[1]);
    AES_writeReg(EF_AES_BLOCK2_OFFSET, block[2]);
    AES_writeReg(EF_AES_BLOCK3_OFFSET, block[3]);
    
    // Start operation
    uint32_t ctrl = EF_AES_CTRL_NEXT;
    if (mode == AES_DECRYPT) {
        ctrl |= EF_AES_CTRL_DECRYPT;
    }
    AES_writeReg(EF_AES_CTRL_OFFSET, ctrl);
    
    return AES_OK;
}

AES_Status_t AES_readResult(uint32_t result[4]) {
    if (result == NULL) {
        return AES_ERR_NULL_PTR;
    }
    
    // Check if result is valid
    if (!AES_isValid()) {
        return AES_ERR_NOT_READY;
    }
    
    // Read result
    result[0] = AES_readReg(EF_AES_RESULT0_OFFSET);
    result[1] = AES_readReg(EF_AES_RESULT1_OFFSET);
    result[2] = AES_readReg(EF_AES_RESULT2_OFFSET);
    result[3] = AES_readReg(EF_AES_RESULT3_OFFSET);
    
    return AES_OK;
}

// ============================================================================
// Interrupt Management Functions
// ============================================================================

void AES_enableInterrupt(void) {
    AES_writeReg(EF_AES_IM_OFFSET, EF_AES_IRQ_DONE);
}

void AES_disableInterrupt(void) {
    AES_writeReg(EF_AES_IM_OFFSET, 0);
}

bool AES_getInterruptStatus(void) {
    uint32_t ris = AES_readReg(EF_AES_RIS_OFFSET);
    return (ris & EF_AES_IRQ_DONE) != 0;
}

void AES_clearInterrupt(void) {
    AES_writeReg(EF_AES_IC_OFFSET, EF_AES_IRQ_DONE);
}

// ============================================================================
// Utility Functions
// ============================================================================

void AES_bytesToWords(const uint8_t *bytes, uint32_t *words, uint32_t num_words) {
    for (uint32_t i = 0; i < num_words; i++) {
        words[i] = ((uint32_t)bytes[i*4 + 0]) |
                   ((uint32_t)bytes[i*4 + 1] << 8) |
                   ((uint32_t)bytes[i*4 + 2] << 16) |
                   ((uint32_t)bytes[i*4 + 3] << 24);
    }
}

void AES_wordsToBytes(const uint32_t *words, uint8_t *bytes, uint32_t num_words) {
    for (uint32_t i = 0; i < num_words; i++) {
        bytes[i*4 + 0] = (uint8_t)(words[i] & 0xFF);
        bytes[i*4 + 1] = (uint8_t)((words[i] >> 8) & 0xFF);
        bytes[i*4 + 2] = (uint8_t)((words[i] >> 16) & 0xFF);
        bytes[i*4 + 3] = (uint8_t)((words[i] >> 24) & 0xFF);
    }
}
