#include "ndef.h"

enum{
	TLV_T = 0,
	TLV_L0,
	TLV_L1,
	TLV_L2,
	TLV_V,
};
uint8_t TLV_STATE;

enum{
	NDEF_TNF_FLAG = 0,
	NDEF_TYPE_LEN,
	NDEF_PAY_LEN0,
	NDEF_PAY_LEN1,
	NDEF_PAY_LEN2,
	NDEF_PAY_LEN3,
	NDEF_ID_LEN,
	NDEF_TYPE_PAY,
	NDEF_ID_PAY,
	NDEF_PAYLOAD
};
uint8_t NDEF_STATE;

// NDEF Type Name Format
enum{
	TNF_EMPTY = 0,
	TNF_WELL_KNOWN,
	TNF_MIME_2046,
	TNF_URI_3986,
	TNF_EXTERNAL,
	TNF_UNKNOWN,
	TNF_UNCHANGED,
	TNF_RESERVED
};

union rxbuffer{
	uint8_t mfc1k[1024];
}rxBuffer;

union txbuffer{
	uint8_t mfc1k[1024];
}txBuffer;

tlv_t 		ndefRx;
tlv_t 		ndefTx;

ndef_t* lastRecord;

uint32_t payTypeCnt;
uint32_t payIdCnt;
uint32_t payCnt;

void parseNDEF(uint8_t* data);

int NDEF_init(uint8_t loop){

	ndefTx.tlv      = 0x03;
	ndefTx.tlvLen 	= 0;
	ndefTx.msgCount = 0;
	
	TLV_STATE 	= TLV_T;
	NDEF_STATE	= NDEF_TNF_FLAG;
	
	if(NFC_init(loop)){
		return 1;
	}
	if(NFC_start()){
		return 1;
	}
	return 0;
}

void NDEF_exit(void){
	NFC_stop();
}

int NDEF_addRecord(uint8_t tnf,uint8_t typeLen,uint32_t payLen,uint8_t idLen,uint8_t* payType,uint8_t* payId,uint8_t* payload){
	
	if(ndefTx.msgCount>100){
		return 1;
	}
	
	ndefTx.tlvLen += 1+1+typeLen+payLen+idLen;
	if(ndefTx.msgCount==0)
		ndefTx.msg[ndefTx.msgCount].msgBegin = 1;
	else
		ndefTx.msg[ndefTx.msgCount].msgBegin = 0;
	
	ndefTx.msg[ndefTx.msgCount].msgEnd 		= 0;
	ndefTx.msg[ndefTx.msgCount].msgChunked 	= 0;
	
	if(payLen<0x100){
		ndefTx.tlvLen += 1;
		ndefTx.msg[ndefTx.msgCount].shortRec = 1;
	}
	else{
		ndefTx.tlvLen += 4;
		ndefTx.msg[ndefTx.msgCount].shortRec = 0;
	}
	
	if(idLen>0){
		ndefTx.tlvLen += 1;
		ndefTx.msg[ndefTx.msgCount].idLenValid = 1;
	}
	else{
		ndefTx.msg[ndefTx.msgCount].idLenValid = 0;
	}
	
	ndefTx.msg[ndefTx.msgCount].tnf = tnf&0x07;
	
	ndefTx.msg[ndefTx.msgCount].typeLen = typeLen;
	ndefTx.msg[ndefTx.msgCount].payLen  = payLen;
	ndefTx.msg[ndefTx.msgCount].idLen   = idLen;
	
	ndefTx.msg[ndefTx.msgCount].payType = payType;
	ndefTx.msg[ndefTx.msgCount].payId   = payId;
	ndefTx.msg[ndefTx.msgCount].payload = payload;
	
	lastRecord = &ndefTx.msg[ndefTx.msgCount];
	
	ndefTx.msgCount++;
	
	return 0;
}

int NDEF_writeRecords(uint8_t* uid,uint16_t uidSize){

	lastRecord->msgEnd = 1;
	uint32_t txIndex = 0;
	uint32_t i,j;
	uint8_t flagTnf = 0;
	
	if(ndefTx.msgCount<0){
		return 1;
	}
	
	//printf("Tlv length : %02X %d",ndefTx.tlvLen,ndefTx.tlvLen);
	
	txBuffer.mfc1k[txIndex++] = 0;
	txBuffer.mfc1k[txIndex++] = 0;
	txBuffer.mfc1k[txIndex++] = ndefTx.tlv;
	if(ndefTx.tlvLen>0xFE){
		txBuffer.mfc1k[txIndex++] = 0xFF;
		txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.tlvLen>>8);
		txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.tlvLen);
	}
	else{
		txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.tlvLen);
	}
	
	for(i=0;i<ndefTx.msgCount;i++){
		flagTnf   = ndefTx.msg[i].msgBegin;
		flagTnf <<=1;
		flagTnf  |= ndefTx.msg[i].msgEnd;
		flagTnf <<=1;
		flagTnf  |= ndefTx.msg[i].msgChunked;
		flagTnf <<=1;
		flagTnf  |= ndefTx.msg[i].shortRec;
		flagTnf <<=1;
		flagTnf  |= ndefTx.msg[i].idLenValid;
		flagTnf <<=3;
		flagTnf  |= ndefTx.msg[i].tnf;
		
		txBuffer.mfc1k[txIndex++] = flagTnf;
		txBuffer.mfc1k[txIndex++] = ndefTx.msg[i].typeLen;
		
		if(ndefTx.msg[i].shortRec){
			txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.msg[i].payLen);
		}
		else{
			txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.msg[i].payLen>>24);
			txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.msg[i].payLen>>16);
			txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.msg[i].payLen>>8);
			txBuffer.mfc1k[txIndex++] = (uint8_t)(ndefTx.msg[i].payLen);
		}
		if(ndefTx.msg[i].idLenValid){
			txBuffer.mfc1k[txIndex++] = ndefTx.msg[i].idLen;
		}
		if(ndefTx.msg[i].typeLen>0){
			for(j=0;j<ndefTx.msg[i].typeLen;j++){
				txBuffer.mfc1k[txIndex++] = ndefTx.msg[i].payType[j];
			}
		}
		if(ndefTx.msg[i].idLen>0 && ndefTx.msg[i].idLenValid){
			for(j=0;j<ndefTx.msg[i].idLen;j++){
				txBuffer.mfc1k[txIndex++] = ndefTx.msg[i].payId[j];
			}
		}
		if(ndefTx.msg[i].payLen>0){
			for(j=0;j<ndefTx.msg[i].payLen;j++){
				txBuffer.mfc1k[txIndex++] = ndefTx.msg[i].payload[j];
			}
		}
	}
	ndefTx.tlvLen 	= 0;
	ndefTx.msgCount = 0;
	
	txBuffer.mfc1k[txIndex++] = 0xFE;
	
	/*
	for(i=0;i<txIndex;i++){
		if(i%16==0)
			printf("\n");
		if(i%(16*3)==0)
			printf("\n");
	
		printf("%02X ",txBuffer.mfc1k[i]);
	}
	printf("\n");
	*/
	return NFC_mifareClassic1k_write(uid,uidSize,txBuffer.mfc1k,txIndex);
}

void NFC_cardDetected(uint8_t cardType,uint8_t* uid,uint8_t uidSize,uint8_t* atqAB, uint8_t atqLen,uint8_t* sak){
	switch(cardType){
		case mifare_classic_4k:
		break;
		case mifare_mini:
		break;
		case mifare_classic_1k:
			//NFC_mifareClassic1k_memoryDump(uid,uidSize);
			NFC_mifareClassic1k_read(uid,uidSize,rxBuffer.mfc1k,sizeof(rxBuffer.mfc1k));
		break;
		case mifare_plus_4k_sl2:
		break;
		case mifare_plus_2k_sl2:
		break;
		case mifare_part4:
		break;
		case mifare_ultralight:
		break;
		case felica:
		break;
		case typeB:
		break;
	}
}

void NDEF_parseTLV(uint8_t* uid,uint8_t uidSize,uint8_t* data,uint16_t len){

	//NFC_printUidAtqaSak(uid,uidSize,NULL,0,NULL);
	
	int recordFound = 0;
	
	uint16_t byteCount;
	
	ndefRx.uid 		= uid;
	ndefRx.uidSize 	= uidSize;
	ndefRx.msgCount = 0;
	
	int i;
	for(i=0;i<len;i++){
		switch(TLV_STATE){
			case TLV_T:
				// Check for NDEF TLV block
				if(data[i]==0x03){
					ndefRx.tlv = data[i];
					byteCount  = 0;
					TLV_STATE = TLV_L0;
					break;
				}
				if(data[i]==0xFE){
					recordFound = 1;
					// End of TLV block/s
					if(ndefRx.msgCount>0){
						//Signal ndef record processing
						//printf("Perfect \n");
						NDEF_recordFound(ndefRx.msgCount,uid,uidSize,ndefRx.msg);
					}
					else{
					//printf("Msg Count <= 0 \n");
						NDEF_recordFound(0,uid,uidSize,NULL);
					}
					return;
				}
			break;
			case TLV_L0:
				ndefRx.tlvLen = (uint32_t)data[i];
				if(data[i]!=0xFF){
					// TLV block uses 1 byte length format
					if(data[i]>0)
						TLV_STATE = TLV_V;
					else
						TLV_STATE = TLV_T;
					break;
				}
				ndefRx.tlvLen = 0;
				// TLV block uses 3 bytes format
				TLV_STATE = TLV_L1;
			break;
			case TLV_L1:
				ndefRx.tlvLen <<= 8;
				ndefRx.tlvLen |= (uint32_t)data[i];
				TLV_STATE = TLV_L2;
			break;
			case TLV_L2:
				ndefRx.tlvLen <<= 8;
				ndefRx.tlvLen |= (uint32_t)data[i];
				TLV_STATE = TLV_V;
			break;
			case TLV_V:
				parseNDEF(&data[i]);
				byteCount++;
				if(byteCount<ndefRx.tlvLen){
					break;
				}
				TLV_STATE = TLV_T;
			break;
		}
	}
	if(!recordFound && ndefRx.msgCount>0){
		// Broken TLV blocks (Terminator Tag not found)
		//printf("No terminator tag found \n");
		NDEF_recordFound(ndefRx.msgCount,uid,uidSize,ndefRx.msg);
	}
	else{
		// No NDEF messages found
		//printf("No ndef message detected \n");
		NDEF_recordFound(0,uid,uidSize,NULL);
	}
}

void parseNDEF(uint8_t* data){
	
	uint8_t rawData = data[0];
	
	switch(NDEF_STATE){
		case NDEF_TNF_FLAG:
			ndefRx.msg[ndefRx.msgCount].msgBegin	= (rawData>>7)&0x01;
			ndefRx.msg[ndefRx.msgCount].msgEnd	 	= (rawData>>6)&0x01;
			ndefRx.msg[ndefRx.msgCount].msgChunked	= (rawData>>5)&0x01;
			ndefRx.msg[ndefRx.msgCount].shortRec	= (rawData>>4)&0x01;
			ndefRx.msg[ndefRx.msgCount].idLenValid	= (rawData>>3)&0x01;
			ndefRx.msg[ndefRx.msgCount].tnf 		= rawData&0x07;
			
			payTypeCnt	= 0;
			payIdCnt	= 0;
			payCnt		= 0;

			NDEF_STATE = NDEF_TYPE_LEN;
		break;
		case NDEF_TYPE_LEN:
			ndefRx.msg[ndefRx.msgCount].typeLen = rawData;
			NDEF_STATE = NDEF_PAY_LEN0;
		break;
		case NDEF_PAY_LEN0:
			ndefRx.msg[ndefRx.msgCount].payLen = (uint32_t)rawData;
			if(!ndefRx.msg[ndefRx.msgCount].shortRec){
				NDEF_STATE = NDEF_PAY_LEN1;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].shortRec && ndefRx.msg[ndefRx.msgCount].idLenValid){
				NDEF_STATE = NDEF_ID_LEN;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].shortRec && !ndefRx.msg[ndefRx.msgCount].idLenValid){
				if(ndefRx.msg[ndefRx.msgCount].typeLen>0){
					NDEF_STATE = NDEF_TYPE_PAY;
					break;
				}
				if(ndefRx.msg[ndefRx.msgCount].payLen>0){
					NDEF_STATE = NDEF_PAYLOAD;
					break;
				}	
			}
			// Empty TNF
			NDEF_STATE = NDEF_TNF_FLAG;
		break;
		case NDEF_PAY_LEN1:
			ndefRx.msg[ndefRx.msgCount].payLen <<= 8;
			ndefRx.msg[ndefRx.msgCount].payLen |= (uint32_t)rawData;
			NDEF_STATE = NDEF_PAY_LEN2;
		break;
		case NDEF_PAY_LEN2:
			ndefRx.msg[ndefRx.msgCount].payLen <<= 8;
			ndefRx.msg[ndefRx.msgCount].payLen |= (uint32_t)rawData;
			NDEF_STATE = NDEF_PAY_LEN3;
		break;
		case NDEF_PAY_LEN3:
			ndefRx.msg[ndefRx.msgCount].payLen <<= 8;
			ndefRx.msg[ndefRx.msgCount].payLen |= (uint32_t)rawData;
			if(ndefRx.msg[ndefRx.msgCount].idLenValid){
				NDEF_STATE = NDEF_ID_LEN;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].typeLen>0){
				NDEF_STATE = NDEF_TYPE_PAY;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].payLen>0){
				NDEF_STATE = NDEF_PAYLOAD;
				break;
			}
			// Something went horribly wrong!
			NDEF_STATE = NDEF_TNF_FLAG;
		break;
		case NDEF_ID_LEN:
			ndefRx.msg[ndefRx.msgCount].idLen = rawData;
			if(ndefRx.msg[ndefRx.msgCount].typeLen>0){
				NDEF_STATE = NDEF_TYPE_PAY;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].idLen>0){
				NDEF_STATE = NDEF_ID_PAY;
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].payLen>0){
				NDEF_STATE = NDEF_PAYLOAD;
				break;
			}
			// Something went horribly wrong!
			NDEF_STATE = NDEF_TNF_FLAG;
		break;
		case NDEF_TYPE_PAY:
			if(payTypeCnt==0)
				ndefRx.msg[ndefRx.msgCount].payType = data;
			payTypeCnt++;
			if(payTypeCnt<ndefRx.msg[ndefRx.msgCount].typeLen)
				break;
			if(ndefRx.msg[ndefRx.msgCount].idLenValid && ndefRx.msg[ndefRx.msgCount].idLen>0){
				NDEF_STATE = NDEF_ID_PAY;
				break;
			}
			if(!ndefRx.msg[ndefRx.msgCount].idLenValid && ndefRx.msg[ndefRx.msgCount].payLen>0){
				NDEF_STATE = NDEF_PAYLOAD;
				break;
			}
			// Something went horribly wrong!
			NDEF_STATE = NDEF_TNF_FLAG;	
		break;
		case NDEF_ID_PAY:
			if(payIdCnt==0){
				ndefRx.msg[ndefRx.msgCount].payId = data;
			}
			payIdCnt++;
			if(payIdCnt < ndefRx.msg[ndefRx.msgCount].idLen){
				break;
			}
			if(ndefRx.msg[ndefRx.msgCount].payLen>0){
				NDEF_STATE = NDEF_PAYLOAD;
				break;
			}
			// Something went horribly wrong!
			NDEF_STATE = NDEF_TNF_FLAG;	
		break;
		case NDEF_PAYLOAD:
			if(payCnt==0){
				ndefRx.msg[ndefRx.msgCount].payload = data;
			}
			payCnt++;
			if(payCnt < ndefRx.msg[ndefRx.msgCount].payLen){
				break;
			}
			ndefRx.msgCount++;
			NDEF_STATE = NDEF_TNF_FLAG;	
		break;
	} 
}