#ifndef __VITAL_H__
#define __VITAL_H__

#include "ndef.h"

typedef struct{
	char id[64];
	char timeStamp[64];
	char name[64];
	char tel[16];
	char center[16];
	char blood[16];
	char infection[16];
}text_t;

typedef struct{
	uint8_t encoding;
	char    lang[2];
	text_t  payload;
}vital_t;

// Provides

int  VITAL_init(uint8_t loop);
void VITAL_exit(void);

void VITAL_setPatientId(vital_t* vital,const char* id);
void VITAL_setTimeStamp(vital_t* vital,const char* time);
void VITAL_setPatientName(vital_t* vital,const char* name);
void VITAL_setPhoneNumber(vital_t* vital,const char* tel);
void VITAL_setCenterName(vital_t* vital,const char* centerName);
void VITAL_setBloodGroup(vital_t* vital,const char* bloodGroup);
void VITAL_setTypeOfInfection(vital_t* vital,const char* infection);

uint8_t VITAL_setPatientData(uint8_t* cardId,uint16_t cardIdSize,vital_t* vital);

const char* VITAL_getPatientId(vital_t* vital);
const char* VITAL_getTimeStamp(vital_t* vital);
const char* VITAL_getPatientName(vital_t* vital);
const char* VITAL_getPhoneNumber(vital_t* vital);
const char* VITAL_getCenterName(vital_t* vital);
const char* VITAL_getBloodGroup(vital_t* vital);
const char* VITAL_getTypeOfInfection(vital_t* vital);

// Uses
void VITAL_patientInfo(uint8_t* cardId,uint16_t cardIdSize,vital_t* data);

#endif