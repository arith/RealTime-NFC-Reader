#include "vital.h"
#include <string.h>

int status,trial;


uint8_t*  cUid;
uint16_t  cUidSize;

vital_t* patInfo;
vital_t* wrPatientInfo;

int VITAL_init(uint8_t loop){
	
	wrPatientInfo = NULL;
	
	status = NDEF_init(loop);
	trial=1;
	if(status){
		return status;
	}
}

void VITAL_exit(void){
	NDEF_exit();
}

void VITAL_setPatientId(vital_t* vital,const char* id){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->id,'\0',sizeof(info->id));
	for(i=0;i<64-1;i++){
		if(id[i]=='\0'){
			break;
		}
		info->id[i] = id[i];
	}
}

void VITAL_setTimeStamp(vital_t* vital,const char* timeStamp){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->timeStamp,'\0',sizeof(info->timeStamp));
	for(i=0;i<64-1;i++){
		if(timeStamp[i]=='\0'){
			break;
		}
		info->timeStamp[i] = timeStamp[i];
	}
}

void VITAL_setPatientName(vital_t* vital,const char* name){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->name,'\0',sizeof(info->name));
	for(i=0;i<64-1;i++){
		if(name[i]=='\0'){
			break;
		}
		info->name[i] = name[i];
	}
}

void VITAL_setPhoneNumber(vital_t* vital,const char* tel){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->tel,'\0',sizeof(info->tel));
	for(i=0;i<16-1;i++){
		if(tel[i]=='\0'){
			break;
		}
		info->tel[i] = tel[i];
	}
}

void VITAL_setCenterName(vital_t* vital,const char* centerName){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->center,'\0',sizeof(info->center));
	for(i=0;i<16-1;i++){
		if(centerName[i]=='\0'){
			break;
		}
		info->center[i] = centerName[i];
	}
}

void VITAL_setBloodGroup(vital_t* vital,const char* bloodGroup){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->blood,'\0',sizeof(info->blood));
	for(i=0;i<16-1;i++){
		if(bloodGroup[i]=='\0'){
			break;
		}
		info->blood[i] = bloodGroup[i];
	}
}

void VITAL_setTypeOfInfection(vital_t* vital,const char* infection){
	int i;
	text_t* info = &vital->payload;
	
	memset(info->infection,'\0',sizeof(info->infection));
	for(i=0;i<16-1;i++){
		if(infection[i]=='\0'){
			break;
		}
		info->infection[i] = infection[i];
	}
}

uint8_t VITAL_setPatientData(uint8_t* cardId,uint16_t cardIdSize, vital_t* vital){

	if(wrPatientInfo!=NULL){
		return 1;
	}
	
	cUid = cardId;
	cUidSize = cardIdSize;
	wrPatientInfo = vital;
	
	return 0;
}

const char* VITAL_getPatientId(vital_t* vital){
	return (const char*)(vital->payload.id);
}

const char* VITAL_getTimeStamp(vital_t* vital){
	return (const char*)(vital->payload.timeStamp);
}

const char* VITAL_getPatientName(vital_t* vital){
	return (const char*)(vital->payload.name);
}

const char* VITAL_getPhoneNumber(vital_t* vital){
	return (const char*)(vital->payload.tel);
}

const char* VITAL_getCenterName(vital_t* vital){
	return (const char*)(vital->payload.center);
}

const char* VITAL_getBloodGroup(vital_t* vital){
	return (const char*)(vital->payload.blood);
}

const char* VITAL_getTypeOfInfection(vital_t* vital){
	return (const char*)(vital->payload.infection);
}

void NDEF_recordFound(uint8_t numOfRecords,uint8_t* uid,uint16_t uidSize,ndef_t* ndefRecord){
	int i;
	int vRec = 0;
	for(i=0;i<numOfRecords;i++){
		if(ndefRecord[i].tnf == 0x01 && ndefRecord[i].payType[0]=='T' && ndefRecord[i].payLen == sizeof(vital_t)){
			//printf("Info matched!\n");
			patInfo = (vital_t*)(ndefRecord[i].payload);
			vRec = 1;
			VITAL_patientInfo(uid,uidSize,patInfo);
			break;
		}
	}
	if(!vRec){
		//printf("No info matched!\n");
		VITAL_patientInfo(uid,uidSize,NULL);
	}
	
	if(wrPatientInfo!=NULL){
		wrPatientInfo->encoding = 0x02;
		wrPatientInfo->lang[0] = 'e';
		wrPatientInfo->lang[1] = 'n';
		
		NDEF_addRecord(0x01,1,259,0,(uint8_t*)("T"),NULL,(uint8_t*)(wrPatientInfo));	
		NDEF_writeRecords(cUid,cUidSize);
	}
	wrPatientInfo = NULL;
}