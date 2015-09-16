#include "nfc.h"
#include <ph_NxpBuild.h>
#include <ph_Status.h>
#include <phpalI14443p3a.h>
#include <phpalI14443p4.h>
#include <phpalI14443p4a.h>
#include <phalMful.h>
#include <phalMfc.h>
#include <phKeyStore.h>
#include <phpalSli15693.h>
#include <phpalSli15693_Sw.h>
#include <phpalFelica.h>
#include <phpalI14443p3b.h>

//////////////////////////////////
#define sak_ul                0x00
#define sak_ulc               0x00
#define sak_mini              0x09
#define sak_mfc_1k            0x08
#define sak_mfc_4k            0x18
#define sak_mfp_2k_sl1        0x08
#define sak_mfp_4k_sl1        0x18
#define sak_mfp_2k_sl2        0x10
#define sak_mfp_4k_sl2        0x11
#define sak_mfp_2k_sl3        0x20
#define sak_mfp_4k_sl3        0x20
#define sak_desfire           0x20
#define sak_jcop              0x28
#define sak_layer4            0x20

#define atqa_ul               0x4400
#define atqa_ulc              0x4400
#define atqa_mfc              0x0200
#define atqa_mfp_s            0x0400
#define atqa_mfp_s_2K         0x4400
#define atqa_mfp_x            0x4200
#define atqa_desfire          0x4403
#define atqa_jcop             0x0400
#define atqa_mini             0x0400
#define atqa_nPA              0x0800

#define NUMBER_OF_KEYENTRIES        NUM_OF_DEF_KEYS
#define NUMBER_OF_KEYVERSIONPAIRS   2
#define NUMBER_OF_KUCENTRIES        1
#define DATA_BUFFER_LEN				20

uint8_t mode;

enum{
	D_AB_AB = 2,
	V_AB_XX,
	D_AB_XX,
	D_XB_XB,
	D_AB_XB,
	D_XB_XX,
	V_AB_XB,
	D_XX_XX,
	
	T_XX_AX__AX_XX__AX_AX,
	T_XX_AX__AX_AX__AX_AX,
	T_XX_XX__AX_XX__AX_XX,
	T_XX_XB__AB_XB__XX_XB,
	T_XX_XB__AB_XX__XX_XB,
	T_XX_XX__AB_XB__XX_XX,
	T_XX_XX__AB_XX__XX_XX,
	
	AUTH_A,
	AUTH_B,
	AUTH_X
};

struct timespec ts;

phbalReg_RpiSpi_DataParams_t 	spi_balReader;
void 							*balReader;

phhalHw_Rc523_DataParams_t 		halReader;
void 							*pHal;

phpalI14443p4_Sw_DataParams_t 	I14443p4;
phpalI14443p3a_Sw_DataParams_t 	I14443p3a;

phpalMifare_Sw_DataParams_t 	palMifare;

phalMfc_Sw_DataParams_t 		alMfc;
phalMful_Sw_DataParams_t 		alMful;

phKeyStore_Sw_DataParams_t         SwkeyStore;
phKeyStore_Sw_KeyEntry_t           pKeyEntries[NUMBER_OF_KEYENTRIES];
phKeyStore_Sw_KeyVersionPair_t     pKeyVersionPairs[NUMBER_OF_KEYVERSIONPAIRS * NUMBER_OF_KEYENTRIES];
phKeyStore_Sw_KUCEntry_t           pKUCEntries[NUMBER_OF_KUCENTRIES];

phStatus_t status;

uint8_t bHalBufferReader[0x40];
uint8_t	bDataBuffer[DATA_BUFFER_LEN];
uint8_t mifare_classic_1k_data[1024];
uint8_t bUid[10];
uint8_t aUid[10];
uint8_t aUidSize;
uint8_t bUidSize;
uint8_t pAtqa[2];
uint8_t bSak[1];

uint8_t  bMoreCardsAvailable;
uint32_t sak_atqa;
uint8_t  detected_card;

int IO_init(void);
int BAL_init(void);
int HAL_init(void);

uint8_t DetectMifare(void *halReader);
uint8_t IterateMifare(void);

phStatus_t readerIC_Cmd_SoftReset(void *halReader);

uint8_t started;
uint8_t isDetected;

static int mfc1kSectorKeyEntryA[16];
static int mfc1kSectorKeyEntryB[16];

uint8_t mfc1k_trailerCode[20][4];

void mfc1k_keyDiscovery(uint8_t* uid, uint16_t uidSize);
uint8_t mfc1k_getAccessCondition(uint8_t trailer[][4],uint8_t sector,uint8_t block);

PI_THREAD(start_poll){
	for(;;){
		piLock(0);
		if(!started){
			phhalHw_FieldOff(pHal);
			piUnlock(0);
			return 0;
		}
		piUnlock(0);
		
		nanosleep(&ts,NULL);
		NFC_ping();
		if (!DetectMifare(pHal)){
			NFC_removeCard();
			piLock(0);
			if(!started){
				piUnlock(0);
				return 0;
			}
			piUnlock(0);
			isDetected = 1;
		}
		else{
			NFC_placeCard();
			isDetected = 0;
		}
	}
	
	phhalHw_FieldOff(pHal);
}

int NFC_init(uint8_t loop){
	mode = loop;
	
	int keyEntryNum;
	int defKey;
	
	piUnlock(0);
	
	for(defKey=0;defKey<16;defKey++){
		mfc1kSectorKeyEntryA[defKey] = -1;
		mfc1kSectorKeyEntryB[defKey] = -1;
	}
	
	isDetected = 0;
	
	ts.tv_sec  = (800/1000);
	ts.tv_nsec = (800%1000)*1000000;
	
	status = phKeyStore_Sw_Init(&SwkeyStore,sizeof(phKeyStore_Sw_DataParams_t),
							    &pKeyEntries[0],NUMBER_OF_KEYENTRIES,
							    &pKeyVersionPairs[0],NUMBER_OF_KEYVERSIONPAIRS,
							    &pKUCEntries[0],NUMBER_OF_KUCENTRIES);
	if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Software Keys initialization Fail\n");
		return 1;
	}
	
	//Load default keys as KEY A (version 0) KEY B (version 1)
	for(keyEntryNum=1;keyEntryNum<NUM_OF_DEF_KEYS;keyEntryNum++){
		//printf("Key @%d\t",keyEntryNum);
		//NFC_printHexln(Keys[keyEntryNum],6);
		
		status = phKeyStore_FormatKeyEntry(&SwkeyStore, keyEntryNum, PH_KEYSTORE_KEY_TYPE_MIFARE);
		if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Entry Key formatting Fail\n");
			return 1;
		}
		
		//KEY A&B Pair version 0
		status = phKeyStore_SetKey(&SwkeyStore, keyEntryNum, 0, PH_KEYSTORE_KEY_TYPE_MIFARE, &Keys[keyEntryNum][0], 0);
		if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Failed to load KeyA %d\n",keyEntryNum);
			return 1;
		}
	}
	
	//if(IO_init())
	//	return 1;
	if(BAL_init())
		return 1;
	if(HAL_init())
		return 1;
		
	// Turn on NFC ready LED
	//digitalWrite(NFC,HIGH);
	return 0;
}

void NFC_ioInit(void){
	IO_init();
}

int IO_init(void){
	wiringPiSetup();
// Initialize all the LEDs and Buzzer
	pinMode(NFC_BUZZER,OUTPUT); 	//Buzzer
	//pinMode(DESKTOP,OUTPUT);  	//Desktop LED
	//pinMode(FILE,OUTPUT);  		//File LED
	//pinMode(DEVICE,OUTPUT);	 	//Device LED
	//pinMode(ALERT,OUTPUT);		//Alert LED
	pinMode(NFC_GREEN,OUTPUT);		//Card Detect LED
	pinMode(NFC_RED,OUTPUT);	 	//NFC LED
	return 0;
}

void NFC_placeCard(void){
	digitalWrite(NFC_GREEN,HIGH);
	digitalWrite(NFC_RED,LOW);
	digitalWrite(NFC_BUZZER,LOW);
}

void NFC_removeCard(void){
	digitalWrite(NFC_GREEN,HIGH);
	digitalWrite(NFC_RED,HIGH);
	digitalWrite(NFC_BUZZER,HIGH);
	sleep(1);
	digitalWrite(NFC_BUZZER,LOW);
}

void NFC_busy(void){
	digitalWrite(NFC_GREEN,HIGH);
	digitalWrite(NFC_RED,HIGH);
	digitalWrite(NFC_BUZZER,LOW);
}

void NFC_error(void){
	digitalWrite(5,HIGH);
	digitalWrite(2,HIGH);
	sleep(1);
	digitalWrite(5,LOW);
	digitalWrite(2,LOW);
}

int BAL_init(void){
	/* Initialize the Reader BAL (Bus Abstraction Layer) component */
	status = phbalReg_RpiSpi_Init(&spi_balReader, sizeof(phbalReg_RpiSpi_DataParams_t));
    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to initialize SPI\n");
        return 1;
    }
    balReader = (void *)&spi_balReader;
	
	status = phbalReg_OpenPort((void*)balReader);
    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to open bal\n");
        return 1;
    }
	return 0;
}

int HAL_init(void){
	/* we have a board with PN512,
     * but on the software point of view,
     * it's compatible to the RC523 */
    status = phhalHw_Rc523_Init(&halReader,
                                sizeof(phhalHw_Rc523_DataParams_t),
                                balReader,
                                0,
                                bHalBufferReader,
                                sizeof(bHalBufferReader),
                                bHalBufferReader,
                                sizeof(bHalBufferReader));
								
	pHal = &halReader;

    if (PH_ERR_SUCCESS != status){
        printf("Failed to initialize the HAL\n");
        return 1;
    }

    /* Set the HAL configuration to SPI */
    status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_BAL_CONNECTION,
                               PHHAL_HW_BAL_CONNECTION_SPI);
    if (PH_ERR_SUCCESS != status){
        printf("Failed to set hal connection SPI\n");
        return 1;
    }
	return 0;
}

int NFC_start(void){
	
	piLock(0);
	started = 1;
	piUnlock(0);
	
	NFC_placeCard();
	
	switch(mode){
		case 0:
			for(;;){
			if (!DetectMifare(pHal)){
				NFC_removeCard();
				isDetected = 1;
				return 0;
			}
			else{
				isDetected = 0;
				NFC_placeCard();
			}
		}
		break;
		case 1:
			for(;;){
			if (!DetectMifare(pHal)){
				isDetected = 1;
				NFC_removeCard();
				//piLock(0);
				if(started ==0){
					//piUnlock(0);
					return 0;
				}
			}
			else{
				NFC_placeCard();
				isDetected = 0;
			}
		}
		break;
		case 2:
			return piThreadCreate(start_poll);
		break;
	}
}

void NFC_stop(void){
	//piLock(0);
	started = 0;
	digitalWrite(NFC_GREEN,LOW);
	digitalWrite(NFC_RED,LOW);
	digitalWrite(NFC_BUZZER,LOW);
	//piUnlock(0);
}

uint8_t DetectMifare(void *halReader)
{
	NFC_busy();
	sak_atqa = 0;
    /* Initialize the 14443-3A PAL (Protocol Abstraction Layer) component */
    status =  phpalI14443p3a_Sw_Init(&I14443p3a,sizeof(phpalI14443p3a_Sw_DataParams_t), halReader);
	if (PH_ERR_SUCCESS != status)
		return 1;
    /* Initialize the 14443-4 PAL component */
    status =  phpalI14443p4_Sw_Init(&I14443p4,sizeof(phpalI14443p4_Sw_DataParams_t), halReader);
	if (PH_ERR_SUCCESS != status)
		return 1;
    /* Initialize the Mifare PAL component */
    status =  phpalMifare_Sw_Init(&palMifare,sizeof(phpalMifare_Sw_DataParams_t), halReader, &I14443p4);
	if (PH_ERR_SUCCESS != status)
		return 1;
    /* Initialize Ultralight(-C) AL component */
    status =  phalMful_Sw_Init(&alMful,sizeof(phalMful_Sw_DataParams_t), &palMifare, NULL, NULL, NULL);
	if (PH_ERR_SUCCESS != status)
		return 1;
	/* Initialize Classic AL component */
    status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, NULL);
	if (PH_ERR_SUCCESS != status)
		return 1;
    /* Reset the RF field */
    status = phhalHw_FieldReset(halReader);
	if (PH_ERR_SUCCESS != status)
		return 1;
    /* Apply the type A protocol settings
     * and activate the RF field. */
    status = phhalHw_ApplyProtocolSettings(halReader, PHHAL_HW_CARDTYPE_ISO14443A);
	if (PH_ERR_SUCCESS != status)
		return 1;
		
    /* Empty the pAtqa */
    memset(pAtqa, '\0', 2);
    
	/* Send ReqA*/
	status = phpalI14443p3a_RequestA(&I14443p3a, pAtqa);
	if (PH_ERR_SUCCESS != status)
		return 1;
		
    /* Reset the RF field */
    status = phhalHw_FieldReset(halReader);
	if (PH_ERR_SUCCESS != status)
		return 1;
	
    /* Empty the bSak */
    memset(bSak, '\0', 1);
	
	return IterateMifare();
}


uint8_t IterateMifare(){
	int k,l,sameCard;
	
	sameCard = 1;
	
	bMoreCardsAvailable = 1;
	/* Activate one card after another
	 * and check it's type. */
	while (bMoreCardsAvailable){
		/* Activate the communication layer part 3
		 * of the ISO 14443A standard. */
		status = phpalI14443p3a_ActivateCard(&I14443p3a,NULL, 0x00, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
		
		for(k=0;k<bUidSize;k++){
			aUid[k] = bUid[k];
		}
		aUidSize = bUidSize;
		
		sak_atqa = bSak[0] << 24 | pAtqa[0] << 8 | pAtqa[1];
		sak_atqa &= 0xFFFF0FFF;
		
		if (!status){
			if(bSak[0]>>1 &0x01){
				return 1;
			}
			if(bSak[0]>>3 &0x01){
				if(bSak[0]>>4 &0x01){
					// MIFARE 4K card
					//printf("\nMIFARE Classic 4K detected\n");
					detected_card = mifare_classic_4k;
					status = phpalI14443p3a_HaltA(&I14443p3a);
					if (PH_ERR_SUCCESS != status)
						return 1;
					if(!isDetected){
						NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
					}
					else{
						for(l=0;l<bUidSize;l++){
							if(aUid[l]!=bUid[l]){
								sameCard = 0;
							}
						}
						if(!sameCard){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
					}
				}
				else{
					if(bSak[0] &0x01){
						//MIFARE Mini
						//printf("\nMIFARE Mini detected\n");
						detected_card = mifare_mini;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}
					else{
						// MIFARE CLassic 1k 
						//printf("\nMIFARE Classic 1k detected\n");
						detected_card = mifare_classic_1k;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							mfc1k_keyDiscovery(aUid,aUidSize);
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								mfc1k_keyDiscovery(aUid,aUidSize);
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}		
				}
			}
			else{
				if(bSak[0]>>4 &0x01){
					if(bSak[0]&0x01){
						//MIFARE Plus 4k SL2
						//printf("\nMIFARE Plus 4k SL2 detected\n");
						detected_card = mifare_plus_4k_sl2;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}
					else{
						//MIFARE Plus 2K SL2
						//printf("\nMIFARE Plus 2k SL2 detected\n");
						detected_card = mifare_plus_2k_sl2;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}
				}
				else{
					if(bSak[0]>>5 &0x01){
						//ISO/IEC 14443-4 card. Require RATS + PSS
						//printf("\nISO/IEC 14443-4 card (DESFire & PLUS). Require RATS + PSS\n");
						detected_card = mifare_part4;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}
					else{
						//MIFARE UL || MIFARE UL C
						detected_card = mifare_ultralight;
						status = phpalI14443p3a_HaltA(&I14443p3a);
						if (PH_ERR_SUCCESS != status)
							return 1;
						if(!isDetected){
							NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
						}
						else{
							for(l=0;l<bUidSize;l++){
								if(aUid[l]!=bUid[l]){
									sameCard = 0;
								}
							}
							if(!sameCard){
								NFC_cardDetected(detected_card,aUid,aUidSize,pAtqa,2,bSak);
							}
						}
					}
				}
			}
		}
		else{
			// No MIFARE card is in the field
			return 0;
		}
	}

	readerIC_Cmd_SoftReset(pHal);
	return 0;

}

phStatus_t readerIC_Cmd_SoftReset(void *halReader)
{
    phStatus_t status = PH_ERR_INVALID_DATA_PARAMS;

    switch (PH_GET_COMPID(halReader))
    {
    case PHHAL_HW_RC523_ID:
        status = phhalHw_Rc523_Cmd_SoftReset(halReader);
    break;
    }

    return status;
}

void NFC_mifareClassic1k_memoryDump(uint8_t* uid,uint16_t uidSize){
	
	int loopSector,loopBlock,loop;
	int sCount = 0;
	
	for (loopSector=0;loopSector<0x3FU;loopSector=loopSector+4){
		if(mfc1kSectorKeyEntryA[sCount]>-1){
			status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
					printf("Failed to activate card\n");
					status = phpalI14443p3a_HaltA(&I14443p3a);
					return;
			}
			
			status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
			status = phalMfc_Authenticate(&alMfc, loopSector, PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sCount],0, uid, uidSize);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				status = phpalI14443p3a_HaltA(&I14443p3a);
				printf("Failed to authenticate with KEY A @ Sector %d\n",loopSector);
				return;
			}
		}
		else{
			if(mfc1kSectorKeyEntryB[sCount]>-1){
				status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
				if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
						printf("Failed to activate card\n");
						status = phpalI14443p3a_HaltA(&I14443p3a);
						return;
				}
				
				status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
				status = phalMfc_Authenticate(&alMfc, loopSector, PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sCount],0, uid, uidSize);
				if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
					status = phpalI14443p3a_HaltA(&I14443p3a);
					printf("Failed to authenticate with KEY A @ Sector %d\n",loopSector);
					return;
				}
			}
			else{
				printf("Sector %02X have no known keys\n",loopSector);
				sCount++;
				continue;
			}
		}
		
		for(loopBlock=loopSector;loopBlock<loopSector+4;loopBlock++){
		
			status = phalMfc_Read(&alMfc, loopBlock, bDataBuffer);
			
			if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Failed to read @ %d\n",loopBlock);
				return;
			}
			printf("\t%02X :",loopBlock);
			for (loop = 0; loop < 16; loop++){
				printf("%02X ",bDataBuffer[loop]);
			}
			printf("\n");
		}
		status = phpalI14443p3a_HaltA(&I14443p3a);
		printf("\n");
		
		sCount++;
	}
	return;
}

void NFC_mifareClassic1k_read(uint8_t* uid,uint16_t uidSize,uint8_t* rdBuffer,uint32_t bufferLength){
	if(bufferLength<1024)
		return;

	int byteCount = 0;
	int sectorIndex = 0;
	int loopTrailer;
	
	int loopSector,loopBlock,loop;
	
	for (loopSector=0;loopSector<0x40U;loopSector=loopSector+4){
		//printf("Reading for sector %02X A : %d B: %d\n",loopSector,mfc1kSectorKeyEntryA[sectorIndex],mfc1kSectorKeyEntryB[sectorIndex]);
		
		if(mfc1kSectorKeyEntryA[sectorIndex]>-1){
			status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
					printf("Failed to activate card\n");
					status = phpalI14443p3a_HaltA(&I14443p3a);
					return;
			}
			
			status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
			status = phalMfc_Authenticate(&alMfc, loopSector, PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sectorIndex],0, uid, uidSize);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				status = phpalI14443p3a_HaltA(&I14443p3a);
				printf("Failed to authenticate with KEY A @ Sector %d\n",loopSector);
				return;
			}
			//printf("Reading using KEY A\n");
		}
		else{
			if(mfc1kSectorKeyEntryB[sectorIndex]>-1){
				status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
				if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
						printf("Failed to activate card\n");
						status = phpalI14443p3a_HaltA(&I14443p3a);
						return;
				}
				
				status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
				status = phalMfc_Authenticate(&alMfc, loopSector, PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sectorIndex],0, uid, uidSize);
				if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
					status = phpalI14443p3a_HaltA(&I14443p3a);
					printf("Failed to authenticate with KEY B @ Sector %d\n",loopSector);
					return;
				}
				//printf("Reading using KEY B\n");
			}
			else{
				sectorIndex++;
				//printf("Sector %02X have no known keys\n",loopSector);
				continue;
			}
		}
		
		loopTrailer = 0;
		for(loopBlock=loopSector;loopBlock<loopSector+4;loopBlock++){
			
			status = phalMfc_Read(&alMfc, loopBlock, bDataBuffer);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				status = phpalI14443p3a_HaltA(&I14443p3a);
				printf("Read : Failed to read @sector %d block %d\n",sectorIndex,loopBlock%4);
				continue;
			}
			
			for (loop = 0; loop < 16; loop++){
				if(loopSector==0 || loopBlock==loopSector+3){
					//Process MAD sector and Sector Trailers
					if(loopSector==0 && loopBlock!=loopSector+3){
						//Process MAD sector
					}
					if(loopBlock==loopSector+3){
						//Process sector trailer
						if(loop>5 && loop<10){
							//printf("loop trailer : %d %d %02X\n",sectorIndex,loopTrailer,bDataBuffer[loop]);
							mfc1k_trailerCode[sectorIndex][loopTrailer++] = bDataBuffer[loop];
						}
					}
					continue;
				}
				if(byteCount<bufferLength)
					rdBuffer[byteCount++]=bDataBuffer[loop];
			}
		}
		sectorIndex++;
		
		status = phpalI14443p3a_HaltA(&I14443p3a);
	}
	NDEF_parseTLV(uid,uidSize,rdBuffer,byteCount);
	return;
}

uint8_t NFC_mifareClassic1k_write(uint8_t* uid,uint16_t uidSize,uint8_t* wrBuffer,uint32_t bufferLength){
	status = phpalI14443p3a_HaltA(&I14443p3a);
	// Sanity check	
	if(bufferLength>1024)
		return 1;
	
	uint8_t blockAvailable=0;
	uint8_t writableBlock = 0;
	int i=0;
	int sector,block,access;
	
	//printf("Preparing the card ..!\n");
	
	//Ignore Sector 0
	for(sector=1;sector<16;sector++){
		block = 0;
		if(mfc1kSectorKeyEntryA[sector] == -1 || mfc1kSectorKeyEntryB[sector] == -1){
			// No known public read key or private write key
			//printf("Write : No known Keys @Sector %d.. \n",sector);
			continue;
		}
		access = mfc1k_getAccessCondition(mfc1k_trailerCode,sector,3);
		if(access==1){
			//printf("Write: Bad sector @ Sector %d\n",sector);
			continue;
		}
		
		switch(access){
			case T_XX_XB__AB_XB__XX_XB:
				//printf("Write: T_XX_XB__AB_XB__XX_XB @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
				if(mfc1kSectorKeyEntryA[sector] != PASSWORD){
					//printf("Write: set Key A @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyA(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				if(mfc1kSectorKeyEntryB[sector] != PASSWORD){
					//printf("Write: set Key B @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyB(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				for(block=0;block<3;block++){
					//printf("Write: Get Access Condition @ Sector %d block %d\n",sector,block);
					if(mfc1k_getAccessCondition(mfc1k_trailerCode,sector,block)!=D_AB_XB){
						//printf("Write: Set write protected @ Sector %d block %d\n",sector,block);
						if(NFC_mfc1k_setWriteProtected(uid,uidSize,sector,block,AUTH_B,AUTH_B)){
							return 1;
						}
					}
					blockAvailable++;
				}
			break;
			case T_XX_XX__AB_XB__XX_XX:
				//printf("Write: T_XX_XX__AB_XB__XX_XX @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
				//printf("Write: Set write protected @ Sector %d block %d\n",sector,0);
				if(NFC_mfc1k_setWriteProtected(uid,uidSize,sector,0,AUTH_B,AUTH_B)){
					return 1;
				}
				if(mfc1kSectorKeyEntryA[sector] != PASSWORD){
					//printf("Write: set Key A @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyA(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				if(mfc1kSectorKeyEntryB[sector] != PASSWORD){
					//printf("Write: set Key B @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyB(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				blockAvailable++;
				for(block=1;block<3;block++){
					//printf("Write: Get Access Condition @ Sector %d block %d\n",sector,block);
					if(mfc1k_getAccessCondition(mfc1k_trailerCode,sector,block)!=D_AB_XB){
						//printf("Write: Set write protected @ Sector %d block %d\n",sector,0);
						if(NFC_mfc1k_setWriteProtected(uid,uidSize,sector,block,AUTH_B,AUTH_B)){
							return 1;
						}
					}
					blockAvailable++;
				}
			break;
			case T_XX_AX__AX_AX__AX_AX:
				//printf("Write: T_XX_AX__AX_AX__AX_AX @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
				//printf("Write: Set write protected @ Sector %d block %d\n",sector,0);
				if(NFC_mfc1k_setWriteProtected(uid,uidSize,sector,0,AUTH_A,AUTH_A)){
					return 1;
				}
				if(mfc1kSectorKeyEntryA[sector] != PASSWORD){
					//printf("Write: set Key A @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyA(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				if(mfc1kSectorKeyEntryB[sector] != PASSWORD){
					//printf("Write: set Key B @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyB(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				blockAvailable++;
				for(block=1;block<3;block++){
					//printf("Write: Get Access Condition @ Sector %d block %d\n",sector,block);
					if(mfc1k_getAccessCondition(mfc1k_trailerCode,sector,block)!=D_AB_XB){
						//printf("Write: Set write protected @ Sector %d block %d\n",sector,block);
						if(NFC_mfc1k_setWriteProtected(uid,uidSize,sector,block,AUTH_B,AUTH_B)){
							return 1;
						}
					}
					blockAvailable++;
				}
			break;
			case T_XX_XB__AB_XX__XX_XB:
				//printf("Write: T_XX_XB__AB_XX__XX_XB @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
				writableBlock = 0;
				for(block=1;block<3;block++){
					//printf("Write: Get Access Condition @ Sector %d block %d\n",sector,block);
					if(mfc1k_getAccessCondition(mfc1k_trailerCode,sector,block)!=D_AB_XB){
						continue;
					}
					writableBlock++;
				}
				if(writableBlock<1){
					break;
				}
				if(mfc1kSectorKeyEntryA[sector] != PASSWORD){
					//printf("Write: set Key A @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyA(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				if(mfc1kSectorKeyEntryB[sector] != PASSWORD){
					//printf("Write: set Key A @ Sector %d\n",sector);
					if(NFC_mfc1k_setKeyB(uid,uidSize,sector,PASSWORD)){
						return 1;
					}
				}
				blockAvailable += writableBlock;
			break;
			case T_XX_AX__AX_XX__AX_AX:
				//printf("Write: T_XX_AX__AX_XX__AX_AX @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
			break;
			case T_XX_XX__AX_XX__AX_XX:
				//printf("Write: T_XX_XX__AX_XX__AX_XX @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
			break;
			case T_XX_XX__AB_XX__XX_XX:
				//printf("Write: T_XX_XX__AB_XX__XX_XX @ Sector %d  %d|%d\n",sector,mfc1kSectorKeyEntryA[sector],mfc1kSectorKeyEntryB[sector]);
			break;
			// Access Bits is locked forever
		}
		if((blockAvailable*16)<bufferLength){
			continue;
		}
		else{
			break;
		}
	}
	if((blockAvailable*16)<bufferLength){
		// Not enough memory available for our data ..
		return 1;
	}
	
	//printf("Write: Writing to the card ..!\n");

	int sectorCount = 0;
	int loopSector,loopBlock,loop;
	
	for (loopSector=0;loopSector<0x3FU;loopSector=loopSector+4){
		//printf("Write: @sector %02X A :%d B: %d...\n",sectorCount,mfc1kSectorKeyEntryA[sectorCount],mfc1kSectorKeyEntryB[sectorCount]);
		if(loopSector==0){
			sectorCount++;
			continue;
		}
		access = mfc1k_getAccessCondition(mfc1k_trailerCode,sectorCount,3);
		if(access==1){
			printf("Write: Bad sector @ Sector %d\n",sectorCount);
			sectorCount++;
			continue;
		}
		
		if(mfc1kSectorKeyEntryA[sectorCount] != PASSWORD || mfc1kSectorKeyEntryB[sectorCount] != PASSWORD){
			sectorCount++;
			continue;
		}
		
		status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Write: Failed to activate card\n");
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
		status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
		status = phalMfc_Authenticate(&alMfc, loopSector, PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sectorCount],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			status = phpalI14443p3a_HaltA(&I14443p3a);
			printf("Write: Failed to authenticate with KEY B @ Sector %d\n",loopSector);
			return 1;
		}
		
		for(loopBlock=loopSector;loopBlock<loopSector+4;loopBlock++){
			if(loopBlock==loopSector+3){
				// Do not write MAD sector and any sector's trailer!!!
				continue;
			}
			if(mfc1k_getAccessCondition(mfc1k_trailerCode,sectorCount,loopBlock-loopSector)!=D_AB_XB){
				continue;
			}
			//printf("Write: @block %d\n",loopBlock-loopSector);
			for (loop = 0; loop < 16; loop++){
				if(i < bufferLength){
					bDataBuffer[loop] = wrBuffer[i++];
				}
				else{
					bDataBuffer[loop] = 0;
				}
			}
			status = phalMfc_Write(&alMfc, loopBlock, bDataBuffer);
			if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Write: Writing for block @%02X failed\n",loopBlock);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return 1;
			}
			if(i>=bufferLength){
				status = phpalI14443p3a_HaltA(&I14443p3a);
				//printf("Write: Finished 1 %d %d\n",sector,loopBlock-loopSector);
				return 0;;
			}
		}
		
		status = phpalI14443p3a_HaltA(&I14443p3a);
		if(i>=bufferLength){
			//printf("Write: Finished  2 %d %d\n",sector,loopBlock-loopSector);
			return 0;;
		}
		sectorCount++;
	}
}

void mfc1k_keyDiscovery(uint8_t* uid, uint16_t uidSize){
	//printf("Discovering keys ...\n");
	uint8_t  actualKey[12];
	uint16_t keyType;
	
	int abKey;
	
	int successKeyA = -1;
	int successKeyB = -1;
	
	int sectorIdx = 0;
	
	int sector;
	for(sector=0;sector<64;sector=sector+4){
		mfc1kSectorKeyEntryB[sectorIdx] = -1;
		mfc1kSectorKeyEntryA[sectorIdx] = -1;
		
		successKeyA = -1;
		successKeyB = -1;
		
		for(abKey=1;abKey<NUM_OF_DEF_KEYS;abKey++){
			status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Key Discovery: Failed to activate card @ sector %02X\n",sector);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return;
			}
			
			status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Key Discovery: Failed to initiate MFC HAL @ sector %02X\n",sector);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return;
			}
			
			status = phalMfc_Authenticate(&alMfc,sector,PHHAL_HW_MFC_KEYA,abKey,0, uid, uidSize);
			if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS){
				successKeyA = abKey;
				mfc1kSectorKeyEntryA[sectorIdx] = successKeyA;
			}
			
			status = phpalI14443p3a_HaltA(&I14443p3a);
			
			status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Key Discovery: Failed to activate card @ sector %02X\n",sector);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return;
			}
			
			status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Key Discovery: Failed to initiate MFC HAL @ sector %02X\n",sector);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return;
			}
			
			status = phalMfc_Authenticate(&alMfc,sector,PHHAL_HW_MFC_KEYB,abKey,0, uid, uidSize);
			if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS){
				successKeyB = abKey;
				mfc1kSectorKeyEntryB[sectorIdx] = successKeyB;
			}

			status = phpalI14443p3a_HaltA(&I14443p3a);
			if(successKeyA==successKeyB && successKeyA>-1 && successKeyB>-1){
				//printf("Keys found @Sector %02X Key A: %d Key B %d ...\n",sector,successKeyA,successKeyB);
				break;
			}
		}
		sectorIdx++;
	}
	//printf("All Keys discovered ...\n");
}

uint8_t mfc1k_getAccessCondition(uint8_t trailer[][4],uint8_t sector,uint8_t block){
	
	//printf("Get AC: @Sector %d Block %d %02X:%02X:%02X:%02X\n",sector,block,trailer[sector][0],trailer[sector][1],trailer[sector][2],trailer[sector][3]);
	
	uint8_t accessBits [4];
	uint8_t accessBitsB[4];
	
	uint8_t c10b,c11b,c12b,c13b, c20b,c21b,c22b,c23b, c30b,c31b,c32b,c33b,
	        c10 ,c11 ,c12 , c13,  c20, c21, c22, c23,  c30, c31, c32, c33;
	
	c10b = (trailer[sector][0]&(0x01));
	c11b = (trailer[sector][0]&(0x02))>>1;
	c12b = (trailer[sector][0]&(0x04))>>2;
	c13b = (trailer[sector][0]&(0x08))>>3;
	
	c20b = (trailer[sector][0]&(0x10))>>4;
	c21b = (trailer[sector][0]&(0x20))>>5;
	c22b = (trailer[sector][0]&(0x40))>>6;
	c23b = (trailer[sector][0]&(0x80))>>7;
	
	c30b = (trailer[sector][1]&(0x01));
	c31b = (trailer[sector][1]&(0x02))>>1;
	c32b = (trailer[sector][1]&(0x04))>>2;
	c33b = (trailer[sector][1]&(0x08))>>3;
	
	c10 = (trailer[sector][1]&(0x10))>>4;
	c11 = (trailer[sector][1]&(0x20))>>5;
	c12 = (trailer[sector][1]&(0x40))>>6;
	c13 = (trailer[sector][1]&(0x80))>>7;
	
	c20 = (trailer[sector][2]&(0x01));
	c21 = (trailer[sector][2]&(0x02))>>1;
	c22 = (trailer[sector][2]&(0x04))>>2;
	c23 = (trailer[sector][2]&(0x08))>>3;
	
	c30 = (trailer[sector][2]&(0x10))>>4;
	c31 = (trailer[sector][2]&(0x20))>>5;
	c32 = (trailer[sector][2]&(0x40))>>6;
	c33 = (trailer[sector][2]&(0x80))>>7;
	
	accessBits[0] = (c10<<2)|(c20<<1)|c30;
	accessBits[1] = (c11<<2)|(c21<<1)|c31;
	accessBits[2] = (c12<<2)|(c22<<1)|c32;
	accessBits[3] = (c13<<2)|(c23<<1)|c33;
	
	accessBitsB[0] = (c10b<<2)|(c20b<<1)|c30b;
	accessBitsB[1] = (c11b<<2)|(c21b<<1)|c31b;
	accessBitsB[2] = (c12b<<2)|(c22b<<1)|c32b;
	accessBitsB[3] = (c13b<<2)|(c23b<<1)|c33b;
	
	// Sanity check
	int i;
	for(i=0;i<sizeof(accessBits);i++){
		if(accessBits[i] != ((~accessBitsB[i])&0x07)){
			printf("Get AC: Access bit checks failed @sector %d block %d\n",sector,block);
			return 1;
		}
	}
	
	//printf("Get Ac: Memory Access for @sector %d block %d : %02X\n",sector,block,accessBits[block]);
	if(block!=3){
		switch(accessBits[block]){
			case 0x00:
				//printf("Get Ac: Data Block (Def) R: KEY A|B  W: KEY A|B @Sector %d Block %d\n",sector,block);
				return D_AB_AB;
			break;
			case 0x01:
				//printf("Get Ac: Data Block (I/D) R: KEY A|B  W: NEVER @Sector %d Block %d\n",sector,block);
				return V_AB_XX;
			break;
			case 0x02:
				//printf("Get Ac: Data Block (R/W) R: KEY A|B  W: NEVER @Sector %d Block %d\n",sector,block);
				return D_AB_XX;
			break;
			case 0x03:
				//printf("Get Ac: Data Block (R/W) R: KEY B  W: KEY B @Sector %d Block %d\n",sector,block);
				return D_XB_XB;
			break;
			case 0x04:
				//printf("Get Ac: Data Block (R/W) R: KEY A|B  W: KEY B @Sector %d Block %d\n",sector,block);
				return D_AB_XB;
			break;
			case 0x05:
				//printf("Get Ac: Data Block (R/W) R: KEY B  W: NEVER @Sector %d Block %d\n",sector,block);
				return D_XB_XX;
			break;
			case 0x06:
				//printf("Get Ac: Data Block (I/D) R: KEY A|B  W: KEY B @Sector %d Block %d\n",sector,block);
				return V_AB_XB;
			break;
			case 0x07:
				//printf("Get Ac: Data Block (R/W) R: NEVER  W: NEVER @Sector %d Block %d\n",sector,block);
				return D_XX_XX;
			break;
		}
	}
	if(block==3){
		switch(accessBits[block]){
			case 0x00:
				//printf("Get Ac: Key A (R:X W:A) Access Bits (R:A W:X) Key B (R:A W:B) @Sector %d Block %d\n",sector,block);
				return T_XX_AX__AX_XX__AX_AX;
			break;
			case 0x01:
				//printf("Get Ac: Key A (R:X W:A) Access Bits (R:A W:A) Key B (R:A W:A) @Sector %d Block %d\n",sector,block);
				return T_XX_AX__AX_AX__AX_AX;
			break;
			case 0x02:
				//printf("Get Ac: Key A (R:X W:X) Access Bits (R:A W:X) Key B (R:A W:X) @Sector %d Block %d\n",sector,block);
				return T_XX_XX__AX_XX__AX_XX;
			break;
			case 0x03:
				//printf("Get Ac: Key A (R:X W:B) Access Bits (R:A|B W:B) Key B (R:X W:B) @Sector %d Block %d\n",sector,block);
				return T_XX_XB__AB_XB__XX_XB;
			break;
			case 0x04:
				//printf("Get Ac: Key A (R:X W:B) Access Bits (R:A|B W:X) Key B (R:X W:B) @Sector %d Block %d\n",sector,block);
				return T_XX_XB__AB_XX__XX_XB;
			break;
			case 0x05:
				//printf("Get Ac: Key A (R:X W:X) Access Bits (R:A|B W:B) Key B (R:X W:X) @Sector %d Block %d\n",sector,block);
				return T_XX_XX__AB_XB__XX_XX;
			break;
			case 0x06:
				//printf("Get Ac: Key A (R:X W:X) Access Bits (R:A|B W:X) Key B (R:X W:X) @Sector %d Block %d\n",sector,block);
				return T_XX_XX__AB_XX__XX_XX;
			break;
			case 0x07:
				//printf("Get Ac: Key A (R:X W:X) Access Bits (R:A|B W:X) Key B (R:X W:X) @Sector %d Block %d\n",sector,block);
				return T_XX_XX__AB_XX__XX_XX;
			break;
		}
	}
	return 1;
}

uint8_t NFC_mfc1k_setKeyA(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t keyIndex){
	
	if(keyIndex == mfc1kSectorKeyEntryA[sector]){
		//printf("Set Key A: No changes of Key A for @ sector %02X\n",sector);
		return 0;
	}
	
	status = phpalI14443p3a_HaltA(&I14443p3a);
	int i;
	
	uint8_t  writeBuffer[32];
	uint8_t  actualKey[12];
	uint16_t keyType;
	
	if(mfc1kSectorKeyEntryA[sector]<0 || sector<0 || sector>15){
		printf("Set Key A: No Known Key A for @ sector %02X\n",sector);
		return 1;
	}
	if(mfc1kSectorKeyEntryB[sector]<0 || sector<0 || sector>15){
		printf("Set Key A: No Known Key B for @ sector %02X\n",sector);
		return 1;
	}
	/*
	if(mfc1k_getAccessCondition(mfc1k_trailerCode,sector,3)!=XX_XB__AB_XB__XX_XB){
		printf("Set Key A: Read Only Access for @ sector %02X\n",sector);
		return 1;
	}
	*/
	status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key A: Failed to activate card @ sector %02X\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key A: Failed to initiate MFC HAL @ sector %02X\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key A: Failed to Authenticate @ sector %d using KEY B\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	status = phalMfc_Read(&alMfc,(sector*4)+3,writeBuffer);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		status = phpalI14443p3a_HaltA(&I14443p3a);
		printf("Set Key A: Failed to Read @Sector %d block %d\n",sector,(sector*4)+3);
		return 1;
	}
	
	for(i=0;i<6;i++){
		writeBuffer[i] = Keys[keyIndex][i];
	}
	for(i=10;i<16;i++){
		writeBuffer[i] = Keys[mfc1kSectorKeyEntryB[sector]][i-10+6];
	}
	
	status = phalMfc_Write(&alMfc,(sector*4)+3, writeBuffer);
	
	if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key A: Failed to write @sector block %02X failed\n",sector,(sector*4)+3);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	mfc1kSectorKeyEntryA[sector] = keyIndex;
	
	status = phpalI14443p3a_HaltA(&I14443p3a);
	return 0;
}

uint8_t NFC_mfc1k_setKeyB(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t keyIndex){
	
	if(keyIndex == mfc1kSectorKeyEntryB[sector]){
		return 0;
	}
	
	status = phpalI14443p3a_HaltA(&I14443p3a);
	int i;
	
	uint8_t  writeBuffer[32];
	uint8_t  actualKey[12];
	uint16_t keyType;

	if(mfc1kSectorKeyEntryA[sector]<0 || sector<0 || sector>15){
		printf("Set Key B: No Known Key A for @ sector %02X\n",sector);
		return 1;
	}
	if(mfc1kSectorKeyEntryB[sector]<0 || sector<0 || sector>15){
		printf("Set Key B: No Known Key B for @ sector %02X\n",sector);
		return 1;
	}
	
	status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key B: Failed to activate card @sector %02X\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key B: Failed to initiate MFC HAL @sector %02X\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key B: Failed to Authenticate @sector %d using KEY B\n",sector);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	status = phalMfc_Read(&alMfc,(sector*4)+3,writeBuffer);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		status = phpalI14443p3a_HaltA(&I14443p3a);
		printf("Set Key B: Failed to Read @sector %d block %d\n",sector,(sector*4)+3);
		return 1;
	}
	for(i=0;i<6;i++){
		writeBuffer[i] = Keys[mfc1kSectorKeyEntryA[sector]][i];  
	}
	for(i=10;i<16;i++){
		writeBuffer[i] = Keys[keyIndex][i-10+6];
	}
	status = phalMfc_Write(&alMfc,(sector*4)+3, writeBuffer);
	
	if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Key B: Failed to write @sector %d block @%02X\n",sector,(sector*4)+3);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	mfc1kSectorKeyEntryB[sector] = keyIndex;
	
	status = phpalI14443p3a_HaltA(&I14443p3a);
	return 0;
}

uint8_t NFC_mfc1k_setWriteProtected(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t block,uint8_t rdKey,uint8_t wrKey){
	
	int i;
	uint8_t rdBuffer[16];
	uint8_t readKey[12];
	
	uint16_t keyType;
	
	//status = phpalI14443p3a_HaltA(&I14443p3a);
	//delay(1);
	status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Read: Failed to activate card @sector %02X block\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Read: Failed to initiate MFC HAL @ sector %02X block %d\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	if(rdKey==AUTH_A){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Read: Failed to Authenticate @ sector %d block %d using KEY A\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	
	if(rdKey==AUTH_B){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Read: Failed to Authenticate @ sector %d block %d using KEY B\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	status = phalMfc_Read(&alMfc,(sector*4)+3,rdBuffer);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		status = phpalI14443p3a_HaltA(&I14443p3a);
		printf("Set Wr: Read: Failed to read @sector %d block %d\n",sector,(sector*4)+3);
		return 1;
	}
	
	phKeyStore_GetKey(&SwkeyStore,mfc1kSectorKeyEntryA[sector],0,12,readKey,&keyType);
	for(i=0;i<6;i++){
		rdBuffer[i] = readKey[i];
	}
	for(i=10;i<16;i++){
		rdBuffer[i] = readKey[6+(i-10)];
	}
	
	switch(block){
		case 0: // C10 C20 C30 = 100 /011
			rdBuffer[7] = rdBuffer[7]|0x10;
			rdBuffer[8] = rdBuffer[8]&0xFE;
			rdBuffer[8] = rdBuffer[8]&0xEF;
			
			rdBuffer[6] = rdBuffer[6]&0xFE;
			rdBuffer[6] = rdBuffer[6]|0x10;
			rdBuffer[7] = rdBuffer[7]|0x01;
		break;
		case 1:
			rdBuffer[7] = rdBuffer[7]|0x20;
			rdBuffer[8] = rdBuffer[8]&0xFD;
			rdBuffer[8] = rdBuffer[8]&0xDF;
			
			rdBuffer[6] = rdBuffer[6]&0xFD;
			rdBuffer[6] = rdBuffer[6]|0x20;
			rdBuffer[7] = rdBuffer[7]|0x02;
		break;
		case 2:
			rdBuffer[7] = rdBuffer[7]|0x40;
			rdBuffer[8] = rdBuffer[8]&0xFB;
			rdBuffer[8] = rdBuffer[8]&0xBF;
			
			rdBuffer[6] = rdBuffer[6]&0xFB;
			rdBuffer[6] = rdBuffer[6]|0x40;
			rdBuffer[7] = rdBuffer[7]|0x04;
		break;
		default:
			return 1;
		break;
	}
	
	// C13 C23 C33 =  011/100 
	rdBuffer[7] = rdBuffer[7]&(0x7F);
	rdBuffer[8] = rdBuffer[8]|(0x08); 
	rdBuffer[8] = rdBuffer[8]|(0x80);
			
	rdBuffer[6] = rdBuffer[6]|(0x08);
	rdBuffer[6] = rdBuffer[6]&(0x7F);
	rdBuffer[7] = rdBuffer[7]&(0xF7);
	
	//printf("Set Wr: ");
	//NFC_printHexln(rdBuffer,16);
	
	if(rdKey!=wrKey){
		status = phpalI14443p3a_HaltA(&I14443p3a);
		
		status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Write: Failed to activate card @sector %02X block\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
		
		status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr:  Write: Failed to initiate MFC HAL @ sector %02X block %d\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
		
		if(wrKey==AUTH_A){
			status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sector],0, uid, uidSize);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Set Wr:  Write: Failed to Authenticate @ sector %d block %d using KEY A\n",sector,block);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return 1;
			}
		}
		
		if(wrKey==AUTH_B){
			status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
			if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
				printf("Set Wr:  Write: Failed to Authenticate @ sector %d block %d using KEY B\n",sector,block);
				status = phpalI14443p3a_HaltA(&I14443p3a);
				return 1;
			}
		}
	}
	
	status = phalMfc_Write(&alMfc,(sector*4)+3, rdBuffer);
	if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr:  Write: Failed to write @sector %d block %d\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phpalI14443p3a_HaltA(&I14443p3a);
	
	mfc1k_trailerCode[sector][0] = rdBuffer[6];
	mfc1k_trailerCode[sector][1] = rdBuffer[7];
	mfc1k_trailerCode[sector][2] = rdBuffer[8];
	
	return 0;
}

uint8_t NFC_mfc1k_clrWriteProtected(uint8_t* uid,uint16_t uidSize,uint8_t sector,uint8_t block,uint8_t rdKey,uint8_t wrKey){	
	int i;
	uint8_t rdBuffer[16];
	uint8_t readKey[12];
	
	uint16_t keyType;
	
	//status = phpalI14443p3a_HaltA(&I14443p3a);
	//delay(1);
	status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Failed to activate card @sector %02X block\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Failed to initiate MFC HAL @ sector %02X block %d\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	if(rdKey==AUTH_A){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Failed to Authenticate @ sector%d block %d using KEY A\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	
	if(rdKey==AUTH_B){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Failed to Authenticate @ sector%d block %d using KEY B\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	status = phalMfc_Read(&alMfc,(sector*4)+3,rdBuffer);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		status = phpalI14443p3a_HaltA(&I14443p3a);
		printf("Set Wr: Failed to read @sector %d block %d\n",sector,(sector*4)+3);
		return 1;
	}
	//status = phpalI14443p3a_HaltA(&I14443p3a);
	
	phKeyStore_GetKey(&SwkeyStore,mfc1kSectorKeyEntryA[sector],0,12,readKey,&keyType);
	
	for(i=0;i<6;i++){
		rdBuffer[i] = readKey[i];
	}
	for(i=10;i<16;i++){
		rdBuffer[i] = readKey[6+(i-10)];
	}
	
	switch(block){
		case 0: // C10 C20 C30 = 000 /111
			rdBuffer[7] = rdBuffer[7]&(0xEF);
			rdBuffer[8] = rdBuffer[8]&(0xFE); 
			rdBuffer[8] = rdBuffer[8]&(0xEF);
			
			rdBuffer[6] = rdBuffer[6]|(0x01);
			rdBuffer[6] = rdBuffer[6]|(0x10);
			rdBuffer[7] = rdBuffer[7]|(0x01);
		break;
		case 1: // C11 C21 C31 = 000/111
			rdBuffer[7] = rdBuffer[7]&(0xDF);
			rdBuffer[8] = rdBuffer[8]&(0xFD); 
			rdBuffer[8] = rdBuffer[8]&(0xDF);
			
			rdBuffer[6] = rdBuffer[6]|(0x02);
			rdBuffer[6] = rdBuffer[6]|(0x20);
			rdBuffer[7] = rdBuffer[7]|(0x02);
		break;
		case 2: // C12 C22 C32 = 000/111
			rdBuffer[7] = rdBuffer[7]&(0xBF);
			rdBuffer[8] = rdBuffer[8]&(0xFB); 
			rdBuffer[8] = rdBuffer[8]&(0xBF);
			
			rdBuffer[6] = rdBuffer[6]|(0x04);
			rdBuffer[6] = rdBuffer[6]|(0x40);
			rdBuffer[7] = rdBuffer[7]|(0x04);
		break;
		default:
			return 1;
		break;
	}
	// C13 C23 C33 =  011/100 
	rdBuffer[7] = rdBuffer[7]&(0x7F);
	rdBuffer[8] = rdBuffer[8]|(0x08); 
	rdBuffer[8] = rdBuffer[8]|(0x80);
			
	rdBuffer[6] = rdBuffer[6]|(0x08);
	rdBuffer[6] = rdBuffer[6]&(0x7F);
	rdBuffer[7] = rdBuffer[7]&(0xF7);

	status = phpalI14443p3a_ActivateCard(&I14443p3a,uid,uidSize, bUid,&bUidSize, bSak, &bMoreCardsAvailable);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Failed to activate card @sector %02X block\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	status = phalMfc_Sw_Init(&alMfc,sizeof(phalMfc_Sw_DataParams_t), &palMifare, &SwkeyStore);
	if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Failed to initiate MFC HAL @ sector %02X block %d\n",sector,block);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	if(wrKey==AUTH_A){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYA,mfc1kSectorKeyEntryA[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Failed to Authenticate @ sector%d block %d using KEY A\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	
	if(wrKey==AUTH_B){
		status = phalMfc_Authenticate(&alMfc,(sector*4)+3,PHHAL_HW_MFC_KEYB,mfc1kSectorKeyEntryB[sector],0, uid, uidSize);
		if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
			printf("Set Wr: Failed to Authenticate @ sector%d block %d using KEY B\n",sector,block);
			status = phpalI14443p3a_HaltA(&I14443p3a);
			return 1;
		}
	}
	
	status = phalMfc_Write(&alMfc,(sector*4)+3, rdBuffer);
	
	if((status & PH_ERR_MASK) != PH_ERR_SUCCESS){
		printf("Set Wr: Failed to write @sector %d block %d\n",sector,(sector*4)+3);
		status = phpalI14443p3a_HaltA(&I14443p3a);
		return 1;
	}
	
	status = phpalI14443p3a_HaltA(&I14443p3a);
	
	mfc1k_trailerCode[sector][0] = rdBuffer[6];
	mfc1k_trailerCode[sector][1] = rdBuffer[7];
	mfc1k_trailerCode[sector][2] = rdBuffer[8];
	
	return 0;
}

void NFC_mifareUltralight_memoryDump(uint8_t* uid,uint16_t uidSize){
	
	nanosleep(&ts,NULL);
	
	uint8_t bBufferReader[PHAL_MFUL_READ_BLOCK_LENGTH];
	uint8_t buff[PHAL_MFUL_READ_BLOCK_LENGTH*4];
	uint8_t* record = (uint8_t*)(buff);
	
	uint8_t i=0;
	uint8_t k=0;
	for(i=0;i<16;i=i+4){
		memset(bBufferReader, '\0', PHAL_MFUL_READ_BLOCK_LENGTH);
		status =  phalMful_Read(&alMful, i, bBufferReader);
		int j;
		for(j = 0; j < PHAL_MFUL_READ_BLOCK_LENGTH; j++){
			record[k] = bBufferReader[j];
			k++;
		}
	}
	
	int c=1;
	int a=0;
	printf("\t %02X:",a++);
	for(k=0;k<PHAL_MFUL_READ_BLOCK_LENGTH*4;k++){
		printf(" %02X", record[k]);
		if(c%4==0 && c<PHAL_MFUL_READ_BLOCK_LENGTH*4){
			int t;
			printf("\t");
			for(t=k-3;t<k+1;t++){
				if(record[t] >31 && record[t]<128){
					printf("%c ",record[t]);
				}
				else{
					printf(". ");
				}
			}
			printf("\n");
			printf("\t %02X:",a++);
		}
		c++;
	}
	printf("\n\n");
}

void NFC_mifareUltralight_rdNdefRecord(uint8_t* uid,uint16_t uidSize){
	nanosleep(&ts,NULL);
}

void NFC_mifareUltralight_wrNdefRecord(uint8_t* uid,uint16_t uidSize){
	nanosleep(&ts,NULL);
}


void NFC_printUidAtqaSak(uint8_t* bUid, uint8_t bLength, uint8_t* pAtqa,uint8_t atqLen,uint8_t* bsak){
	printf("UID: ");
	uint8_t i;
	for(i = 0; i < bLength; i++)
	{
		printf("%02X ", bUid[i]);
	}
	printf("   ");
	
	if(pAtqa!=NULL){
		printf("ATQA: ");
		uint8_t j;
		for(j = atqLen; j > 0; j--)
		{
			printf("%02X ", pAtqa[j-1]);
		}
		printf("   ");
	}
	if(bsak!=NULL){
		printf("SAK: ");
		printf("%02X ", bSak[0]);
	}
	printf("\n\n");
}

void NFC_printString(uint8_t* str,uint16_t len){
	int i;
	for(i=0;i<len;i++){
		printf("%c",str[i]);
	}
}
void NFC_printStringln(uint8_t* str,uint16_t len){
	int i;
	for(i=0;i<len;i++){
		printf("%c",str[i]);
	}
	printf("\n");
}

void NFC_printHex(uint8_t* hex,uint16_t len){
	int i;
	for(i=0;i<len;i++){
		printf("%2X ",hex[i]);
	}
}

void NFC_printHexln(uint8_t* hex,uint16_t len){
	int i;
	for(i=0;i<len;i++){
		printf("%02X ",hex[i]);
	}
	printf("\n");
}