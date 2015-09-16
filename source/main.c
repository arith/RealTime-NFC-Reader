#include "vital.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <wiringPi.h>
#include <stdio.h>
#include <json/json.h>
#include <stdio.h>

int status;
int count;
int mode;

int sockfd;
int readLen;

uint8_t readBuff[256];

char serverIp[] = "127.0.0.1";
int  portno 	= 6969;

struct sockaddr_in 	serverAddr;
struct hostent 		*server;

vital_t newPatient;
time_t  timeStamp;

struct timespec timeOut;

void sendData(const char* data,uint16_t len);

json_object *jObject;

json_object *jPatientId;
json_object *jTimestamp;
json_object *jName;
json_object *jTel;
json_object *jCenter;
json_object *jBlood;
json_object *jInfection;

int main(int argc, char **argv){
	mode  = 0;
	count = 0;

	NFC_ioInit();
	NFC_error();
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		NFC_error();
		printf("Error opening socket\n");
		exit(1);
	}
	
	if ((server = gethostbyname(serverIp)) == NULL ){
        NFC_error();
		printf("Error, no such host\n");
		exit(1);
	}
	
	bzero((char *)&serverAddr,sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,(char *)&serverAddr.sin_addr.s_addr, server->h_length);
    serverAddr.sin_port = htons(portno);
    
	
	printf( "Contacting server\t@%s:%d\n", serverIp, portno );
	while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
		printf("\tConnection error, retrying to connect\t@%s:%d ...\n",serverIp,portno);
		NFC_error();
		sleep(1);
	}
	printf("Successfully connected\t@%s:%d\n\n",serverIp,portno);
	
	timeOut.tv_sec  = 10;
	timeOut.tv_nsec = 10*1000000;
	
	status = VITAL_init(2);
	printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
	for(;;){
	}
	return status;
}

void VITAL_patientInfo(uint8_t* cardId,uint16_t cardIdSize,vital_t* data){

	char* nullMsg = "write_request";

	timeStamp = time(NULL);
	json_object *jobject;
	enum json_type jType;
	
	int itemCount = 0;
	int i;
	printf("\tCard Id\t: ");
	for(i=0;i<cardIdSize;i++){
		printf("%02X ",cardId[i]);
	}
	printf("\n");
	
	if(data==NULL){
	
		printf("\tNo data available, requesting patient info to be written from server ...\n");
		sendData(nullMsg,13);
		printf("\tWaiting for patient info from server ...\n");
		readLen = read(sockfd,readBuff,256);
		while(readLen<1){
			printf("\t\tServer response error, resetting connection...\n",readLen);
			close(sockfd);
			
			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
				printf("Error opening socket\n");
				NFC_error();
				exit(1);
			}
			
			if ((server = gethostbyname(serverIp)) == NULL ){
				printf("Error, no such host\n");
				NFC_error();
				exit(1);
			}
			
			printf("\t\tContacting server @%s:%d\n", serverIp, portno );
			while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
				printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
				sleep(1);
				NFC_error();
			}
			printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		
		if(readBuff[0]=='0'){
			printf("\t\tNo data to be written from server\n");
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		
		printf("\tRceiving patient info to be written from server ...\n");
		readLen = read(sockfd,readBuff,256);
		while(readLen<1){
			printf("\t\tServer response error, resetting connection...\n",readLen);
			close(sockfd);
			
			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
				printf("Error opening socket\n");
				NFC_error();
				exit(1);
			}
			
			if ((server = gethostbyname(serverIp)) == NULL ){
				printf("Error, no such host\n");
				NFC_error();
				exit(1);
			}
			
			printf("\t\tContacting server @%s:%d\n", serverIp, portno );
			while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
				printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
				sleep(1);
				NFC_error();
			}
			printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		printf("\tPatient info received status :%d\n",readLen);
		
		jobject = json_tokener_parse(readBuff);
		
		itemCount = 0;
		json_object_object_foreach(jobject,key,val){
			jType = json_object_get_type(val);
			switch(jType){
				case json_type_string:
					switch(itemCount){
						case 0:
							printf("\t\tPatient Id\t:%s", json_object_get_string(val));
							VITAL_setPatientId(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 1:
							printf("\t\tTime Stamp:\t:%s", json_object_get_string(val));
							VITAL_setTimeStamp(&newPatient,ctime(&timeStamp));
							itemCount++;
						break;
						case 2:
							printf("\t\tName:\t\t:%s", json_object_get_string(val));
							VITAL_setPatientName(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 3:
							printf("\t\tTel:\t\t:%s", json_object_get_string(val));
							VITAL_setPhoneNumber(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 4:
							printf("\t\tCenter:\t\t:%s", json_object_get_string(val));
							VITAL_setCenterName(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 5:
							printf("\t\tBlood:\t\t:%s", json_object_get_string(val));
							VITAL_setBloodGroup(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 6:
							printf("\t\tInfection:\t:%s", json_object_get_string(val));
							VITAL_setTypeOfInfection(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
					}
				break;
			}
		}
		printf("\tWriting to Tag ... \n");
		VITAL_setPatientData(cardId,cardIdSize,&newPatient);
		printf("\tWrite done\n");
		printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
	}
	else{
		jObject 	= json_object_new_object();
		jPatientId	= json_object_new_string(VITAL_getPatientId(data));
		jTimestamp	= json_object_new_string(ctime(&timeStamp));
		jName		= json_object_new_string(VITAL_getPatientName(data));
		jTel		= json_object_new_string(VITAL_getPhoneNumber(data));
		jCenter		= json_object_new_string(VITAL_getCenterName(data));
		jBlood		= json_object_new_string(VITAL_getBloodGroup(data));
		jInfection	= json_object_new_string(VITAL_getTypeOfInfection(data));
		
		json_object_object_add(jObject,"patientId", jPatientId);
		json_object_object_add(jObject,"timestamp", jTimestamp);
		json_object_object_add(jObject,"name", jName);
		json_object_object_add(jObject,"tel", jTel);
		json_object_object_add(jObject,"center", jCenter);
		json_object_object_add(jObject,"blood", jBlood);
		json_object_object_add(jObject,"infection", jInfection);
		
		printf("\tPatient info available, wait for server command ...\n");
		sendData(nullMsg,13);
		printf("\tReceiving server command ...\n");
		readLen = read(sockfd,readBuff,256);
		while(readLen<1){
			printf("\t\tServer response error, resetting connection...\n",readLen);
			close(sockfd);
			
			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
				printf("Error opening socket\n");
				NFC_error();
				exit(1);
			}
			
			if ((server = gethostbyname(serverIp)) == NULL ){
				printf("Error, no such host\n");
				NFC_error();
				exit(1);
			}
			
			printf("\t\tContacting server @%s:%d\n", serverIp, portno );
			while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
				printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
				NFC_error();
				sleep(1);
			}
			printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		
		if(readBuff[0]=='0'){
			printf("\tNo data override request from server, sending patient info to server ...\n");
			printf("\t\tPatient Id\t:%s",VITAL_getPatientId(data));
			printf("\t\tTime Stamp\t:%s",ctime(&timeStamp));
			printf("\t\tName\t\t:%s",VITAL_getPatientName(data));
			printf("\t\tTel\t\t:%s",VITAL_getPhoneNumber(data));
			printf("\t\tCenter\t\t:%s",VITAL_getCenterName(data));
			printf("\t\tBlood\t\t:%s",VITAL_getBloodGroup(data));
			printf("\t\tInfection\t:%s",VITAL_getTypeOfInfection(data));
			
			sendData(json_object_to_json_string(jObject),strlen(json_object_to_json_string(jObject)));
			json_object_put(jObject);
			
			VITAL_setTimeStamp(data,ctime(&timeStamp));
			printf("\tUpdating patient info ...\n");
			VITAL_setPatientData(cardId,cardIdSize,data);
			printf("\tUpdate Done\n");
			
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		
		printf("\tData override request, waiting for patient info ...\n");
		readLen = read(sockfd,readBuff,256);
		while(readLen<1){
			printf("\t\tServer response error, resetting connection...\n",readLen);
			close(sockfd);
			
			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
				printf("Error opening socket\n");
				NFC_error();
				exit(1);
			}
			
			if ((server = gethostbyname(serverIp)) == NULL ){
				printf("Error, no such host\n");
				NFC_error();
				exit(1);
			}
			
			printf("\t\tContacting server @%s:%d\n", serverIp, portno );
			while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
				printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
				NFC_error();
				sleep(1);
			}
			printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
			printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
			return;
		}
		printf("\tPatient info received status :%d\n",readLen);
		
		jobject = json_tokener_parse(readBuff);
		
		itemCount = 0;
		json_object_object_foreach(jobject,key,val){
			jType = json_object_get_type(val);
			switch(jType){
				case json_type_string:
					switch(itemCount){
						case 0:
							printf("\t\tPatient Id\t:%s", json_object_get_string(val));
							VITAL_setPatientId(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 1:
							printf("\t\tTime Stamp:\t:%s", json_object_get_string(val));
							VITAL_setTimeStamp(&newPatient,ctime(&timeStamp));
							itemCount++;
						break;
						case 2:
							printf("\t\tName:\t\t:%s", json_object_get_string(val));
							VITAL_setPatientName(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 3:
							printf("\t\tTel:\t\t:%s", json_object_get_string(val));
							VITAL_setPhoneNumber(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 4:
							printf("\t\tCenter:\t\t:%s", json_object_get_string(val));
							VITAL_setCenterName(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 5:
							printf("\t\tBlood:\t\t:%s", json_object_get_string(val));
							VITAL_setBloodGroup(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
						case 6:
							printf("\t\tInfection:\t:%s", json_object_get_string(val));
							VITAL_setTypeOfInfection(&newPatient,json_object_get_string(val));
							itemCount++;
						break;
					}
				break;
			}
		}
		printf("\tWriting to Tag ... \n");
		VITAL_setPatientData(cardId,cardIdSize,&newPatient);
		printf("\tPatient data override done\n");
		printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
	}
}

void sendData(const char* data,uint16_t len){
	int n;
	printf("\t\tRequest status from server ...\n");
	n = write(sockfd, data,len);
	printf("\t\tRequest status response : %d\n",n);
	while(n<0){
		printf("\tServer response error, attempting connection reset procedure ...\n",readLen);
		close(sockfd);
			
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			printf("Error opening socket\n");
			NFC_error();
			exit(1);
		}
			
		if ((server = gethostbyname(serverIp)) == NULL ){
			printf("Error, no such host\n");
			NFC_error();
			exit(1);
		}
			
		printf("\t\tContacting server @%s:%d\n", serverIp, portno );
		while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
			printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
			NFC_error();
			sleep(1);
		}
		printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
		return;
	}
}

void NFC_ping(void){
	int n;
	const char* pingMsg = "ping_request\n";
	//printf("Ping resquest ...\n");
	n = write(sockfd, pingMsg,strlen(pingMsg)-1);
	memset(readBuff, '\0', 256);
	n = read(sockfd,readBuff,256);
	//printf("Ping response :%d\n",n);
	if(n<1){
		printf("\t\tServer response error, resetting connection...\n",n);
		close(sockfd);
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			printf("Error opening socket\n");
			NFC_error();
			exit(1);
		}
		if ((server = gethostbyname(serverIp)) == NULL ){
			printf("Error, no such host\n");
			NFC_error();
			exit(1);
		}
		printf("\t\tContacting server @%s:%d\n", serverIp, portno );
		while(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) < 0){
			printf("\t\t\tConnection error, retrying to connect @%s:%d...\n",serverIp,portno);
			sleep(1);
			NFC_error();
		}
		printf("\t\tSuccessfully connected @ %s:%d\n",serverIp,portno);
		printf("Polling for MIFARE Classic 1K NFC Tag ...\n");
	}
}
