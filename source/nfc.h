#ifndef __NFC_H__
#define __NFC_H__

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <wiringPi.h>
#include <time.h>
#include "ndef.h"
#include <unistd.h>


// Type of Cards//////////////////
#define mifare_ultralight     0x01
#define mifare_ultralight_c   0x02
#define mifare_classic        0x03
#define mifare_classic_1k     0x04
#define mifare_classic_4k     0x05
#define mifare_plus           0x06
#define mifare_plus_2k_sl1    0x07
#define mifare_plus_4k_sl1    0x08
#define mifare_plus_2k_sl2    0x09
#define mifare_plus_4k_sl2    0x0A
#define mifare_plus_2k_sl3    0x0B
#define mifare_plus_4k_sl3    0x0C
#define mifare_desfire        0x0D
#define jcop                  0x0F
#define mifare_mini           0x10
#define nPA                   0x11
#define mifare_part4		  0x12
#define felica				  0x13
#define typeB				  0x14

#define NFC_BUZZER   	25
//#define DESKTOP		29
//#define FILE			28
//#define DEVICE 		27
//#define ALERT			26
#define NFC_GREEN 		5
#define NFC_RED			2

/* Set the key for the Mifare (R) Classic cards. */
#define NUM_OF_DEF_KEYS 16
// Common Default Keys
static/* const */ uint8_t Keys[NUM_OF_DEF_KEYS][12] = 
{{/*A*/0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,/*B*/0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U}, //00    Do not use!
 {/*A*/0xD3U, 0xF7U, 0xD3U, 0xF7U, 0xD3U, 0xF7U,/*B*/0x75U, 0x74U, 0x6DU, 0x76U, 0x69U, 0x75U}, //01	User defined Key
 {/*A*/0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U,/*B*/0x75U, 0x74U, 0x6DU, 0x76U, 0x69U, 0x75U}, //02    User Defined MAD
 {/*A*/0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U,/*B*/0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU}, //03	Default MAD sector
 {/*A*/0xD3U, 0xF7U, 0xD3U, 0xF7U, 0xD3U, 0xF7U,/*B*/0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU}, //04	Default NFC sector
 {/*A*/0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,/*B*/0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU}, //05    Default NFC sector
 
 {/*A*/0xD3U, 0xF7U, 0xD3U, 0xF7U, 0xD3U, 0xF7U,/*B*/0xD3U, 0xF7U, 0xD3U, 0xF7U, 0xD3U, 0xF7U}, //06
 {/*A*/0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,/*B*/0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU}, //07
 {/*A*/0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,/*B*/0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U}, //08
 {/*A*/0x1AU, 0x98U, 0x2CU, 0x7EU, 0x45U, 0x9AU,/*B*/0x1AU, 0x98U, 0x2CU, 0x7EU, 0x45U, 0x9AU}, //09
 {/*A*/0x4DU, 0x3AU, 0x99U, 0xC3U, 0x51U, 0xDDU,/*B*/0x4DU, 0x3AU, 0x99U, 0xC3U, 0x51U, 0xDDU}, //10
 {/*A*/0xB0U, 0xB1U, 0xB2U, 0xB3U, 0xB4U, 0xB5U,/*B*/0xB0U, 0xB1U, 0xB2U, 0xB3U, 0xB4U, 0xB5U}, //11
 {/*A*/0xA0U, 0xB0U, 0xC0U, 0xD0U, 0xE0U, 0xF0U,/*B*/0xA0U, 0xB0U, 0xC0U, 0xD0U, 0xE0U, 0xF0U}, //12
 {/*A*/0xA1U, 0xB1U, 0xC1U, 0xD1U, 0xE1U, 0xF1U,/*B*/0xA1U, 0xB1U, 0xC1U, 0xD1U, 0xE1U, 0xF1U}, //13
 {/*A*/0xC0U, 0xD0U, 0xE0U, 0xF0U, 0xA1U, 0xB1U,/*B*/0xC0U, 0xD0U, 0xE0U, 0xF0U, 0xA1U, 0xB1U}, //14
 {/*A*/0xBBU, 0xBBU, 0xA0U, 0xA1U, 0xA2U, 0xA3U,/*B*/0xBBU, 0xBBU, 0xA0U, 0xA1U, 0xA2U, 0xA3U}  //15
};

#define PASSWORD 4


// Provides
int  NFC_init(uint8_t loop);
int  NFC_start(void);
void NFC_stop(void);

uint8_t NFC_mfc1k_setKeyA(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t keyEntryNum);
uint8_t NFC_mfc1k_setKeyB(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t keyEntryNum);			
uint8_t NFC_mfc1k_lockSettingsForever(uint8_t* uid,uint16_t uidSize,uint8_t sector);

uint8_t NFC_mfc1k_setWriteProtected(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t block,uint8_t rdKey,uint8_t wrKey);			
uint8_t NFC_mfc1k_clrWriteProtected(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t block,uint8_t rdKey,uint8_t wrKey);				

void NFC_mifareClassic1k_memoryDump(uint8_t* uid,uint16_t uidSize);
void NFC_mifareClassic1k_read(uint8_t* uid,uint16_t uidSize,uint8_t* rdBuffer,uint32_t bufferLength);
uint8_t NFC_mifareClassic1k_write(uint8_t* uid,uint16_t uidSize,uint8_t* wrBuffer,uint32_t bufferLength);

void NFC_mifareUltralight_memoryDump(uint8_t* uid,uint16_t uidSize);
void NFC_mifareUltralight_read(uint8_t* uid,uint16_t uidSize,uint8_t* rdBuffer,uint32_t bufferLength);
void NFC_mifareUltralight_write(uint8_t* uid,uint16_t uidSize,uint8_t* wrBuffer,uint32_t bufferLength);

// Uses
void NFC_cardDetected(uint8_t cardType,uint8_t* uid,uint8_t uidSize,uint8_t* atqa_b,uint8_t atqLen,uint8_t* sak);
void NFC_ping(void);

//Utilities
void NFC_printUidAtqaSak(uint8_t* bUid, uint8_t bLength, uint8_t* pAtqa,uint8_t atqLen,uint8_t* bSak);
void NFC_printString(uint8_t* str,uint16_t len);
void NFC_printStringln(uint8_t* str,uint16_t len);
void NFC_printHex(uint8_t* hex,uint16_t len);
void NFC_printHexln(uint8_t* hex,uint16_t len);

void NFC_ioInit(void);
void NFC_placeCard(void);
void NFC_removeCard(void);
void NFC_error(void);
void NFC_busy(void);

#endif