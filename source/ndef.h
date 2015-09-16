#ifndef __NDEF_H__
#define __NDEF_H__

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <wiringPi.h>
#include <time.h>
#include "nfc.h"

typedef struct{
	uint8_t  msgBegin    :1;
	uint8_t  msgEnd      :1;
	uint8_t  msgChunked  :1;
	uint8_t  shortRec    :1;
	uint8_t  idLenValid  :1;
	uint8_t  tnf         :3;
	
	uint8_t  typeLen;
	uint32_t payLen;
	uint8_t  idLen;
	
	uint8_t* payType;
	uint8_t* payId;
	uint8_t* payload;
}ndef_t;

typedef struct{
	uint8_t    tlv;
	uint32_t   tlvLen;
	ndef_t     msg[100];
	uint32_t   msgCount;
	
	uint8_t* uid;
	uint16_t uidSize;
}tlv_t;

// Common NDEF methods
int  NDEF_init(uint8_t loop);
void NDEF_exit(void);

int NDEF_addRecord(uint8_t flag_tnf,uint8_t typeLen,uint32_t payLen,uint8_t idLen,uint8_t* payType,uint8_t* payId,uint8_t* payload);
int NDEF_writeRecords(uint8_t* uid,uint16_t uidSize);

// NDEF Provides
void NDEF_parseTLV(uint8_t* uid,uint8_t uidSize,uint8_t* rawData,uint16_t len);

// NDEF Uses
void NDEF_recordFound(uint8_t numOfRecords,uint8_t* uid,uint16_t uidSize,ndef_t* ndefRecord);

#endif