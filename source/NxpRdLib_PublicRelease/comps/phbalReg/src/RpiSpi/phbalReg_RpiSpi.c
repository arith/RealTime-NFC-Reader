/**
 * \file phbalReg_RpiSpi.c
 * \author Donatien Garnier
 */

#include <ph_Status.h>
#include <phbalReg.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHBAL_REG_RPI_SPI
#include "phbalReg_RpiSpi.h"
#include <stdio.h>
#include <errno.h>

#define RPI_EXPLORE_NFC_SPI_CHANNEL	0
#define RPI_EXPLORE_NFC_SPI_BITRATE	2000000//10000000

/* Raspberry Pi / SPI implementation of BAL using WiringPi */
#include <wiringPi.h>
#include <wiringPiSPI.h>
#include <unistd.h>



//WiringPi pin number / Positions of pin on P1
#define PIN_CS_IN 8//3 -- this is connected to CS
#define PIN_IRQ 4//16
//#define PIN_SDA 11
#define PIN_NRST 11//26

#define PIN_IFSEL0 2//13
#define PIN_IFSEL1 3//15

#define PIN_663PDOWN 5//18

phStatus_t phbalReg_RpiSpi_Init(
                                    phbalReg_RpiSpi_DataParams_t * pDataParams,
                                    uint16_t wSizeOfDataParams
                                    )
{
    if (sizeof(phbalReg_RpiSpi_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);
    }

    PH_ASSERT_NULL (pDataParams);

    pDataParams->wId = PH_COMP_BAL | PHBAL_REG_RPISPI_ID;
    pDataParams->iFd = -1;
    pDataParams->callback = NULL;
    pDataParams->pUserData = NULL;

    //Init RPi pins
    int r = wiringPiSetup();
    if( r != 0 )
    {
    	//Could not init GPIOs (user probably lacks privileges)
    	return PH_ADD_COMPCODE(PH_ERR_RESOURCE_ERROR, PH_COMP_BAL);
    }
    //Configure PIN_CS_IN pin as input
    pinMode(PIN_CS_IN, INPUT);

    //Configure IRQ pin as input
    pinMode(PIN_IRQ, INPUT);

    //Configure SDA pin as input
    //pinMode(PIN_SDA, INPUT);

    //Configure NRST and 663PDOWN pins as output
    pinMode(PIN_NRST, OUTPUT);
    pinMode(PIN_663PDOWN, OUTPUT);

    //Configure IFSEL pins as output
    pinMode(PIN_IFSEL0, OUTPUT);
    pinMode(PIN_IFSEL1, OUTPUT);

    //Initialize pins to select correct interface
    digitalWrite(PIN_IFSEL0, 0);
    digitalWrite(PIN_IFSEL1, 1);

    //Assert 663PDOWN pin
    digitalWrite(PIN_663PDOWN, 0);

    //Assert reset pin
    digitalWrite(PIN_NRST, 0);

    sleep(1);

    //Make sure to deassert NRST
    digitalWrite(PIN_NRST, 1);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_GetPortList(
                                    phbalReg_RpiSpi_DataParams_t * pDataParams,
                                    uint16_t wPortBufSize,
                                    uint8_t * pPortNames,
                                    uint16_t * pNumOfPorts
                                    )
{
    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_SetPort(
                                    phbalReg_RpiSpi_DataParams_t * pDataParams,
                                    uint8_t * pPortName
                                    )
{
    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_OpenPort(
                                    phbalReg_RpiSpi_DataParams_t * pDataParams
                                    )
{
	pDataParams->iFd = wiringPiSPISetup(RPI_EXPLORE_NFC_SPI_CHANNEL, RPI_EXPLORE_NFC_SPI_BITRATE);
	if( pDataParams->iFd < 0 )
	{
		//Could not open port
		return PH_ADD_COMPCODE(PH_ERR_RESOURCE_ERROR, PH_COMP_BAL);
	}

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_ClosePort(
                                  phbalReg_RpiSpi_DataParams_t * pDataParams
                                  )
{
	if( pDataParams->iFd < 0 )
	{
		//Port is not open
		return PH_ADD_COMPCODE(PH_ERR_RESOURCE_ERROR, PH_COMP_BAL);
	}

	//Close file descriptor
	close(pDataParams->iFd);

	pDataParams->iFd = -1;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

static void dump(int dir, uint8_t* buf, size_t size)
{
	int i=0;
	
	if(dir > 0)
	{
		printf("> ");
	}
	else
	{
		printf("< ");
	}
	for(i = 0; i < size; i++)
	{
		printf("%02X ", buf[i]);
	}
	printf("\r\n");
}

phStatus_t phbalReg_RpiSpi_Exchange(
                                  phbalReg_RpiSpi_DataParams_t * pDataParams,
                                  uint8_t * pTxBuffer,
                                  uint16_t wTxLength,
                                  uint16_t wRxBufSize,
                                  uint8_t * pRxBuffer,
                                  uint16_t * pRxLength
                                  )
{
	//Wiring Pi overwrites the buffer that is passed to wiringPiSPIDataRW
	//dump(1, pTxBuffer, wTxLength);
	uint8_t tmp[wTxLength];
	//printf("tx %p, len %d, rx %p, len %p\r\n", pTxBuffer, wTxLength, pRxBuffer, pRxLength);

	if(pRxBuffer != NULL)
	{
		//memcpy(pRxBuffer, pTxBuffer, wTxLength);
	}
	else
	{
		//pRxBuffer = pTxBuffer;
	}
	memcpy(tmp, pTxBuffer, wTxLength);

	//int r = wiringPiSPIDataRW (RPI_EXPLORE_NFC_SPI_CHANNEL, pTxBuffer, wTxLength); //Returns ioctl() return value
	int r = wiringPiSPIDataRW (RPI_EXPLORE_NFC_SPI_CHANNEL, tmp, wTxLength);

    if (r != wTxLength)
    {
    	//printf("Got %d\r\n", r);
        return PH_ADD_COMPCODE(PH_ERR_INTERFACE_ERROR, PH_COMP_BAL);
    }

    if(pRxLength != NULL)
    {
    	if(pRxBuffer != NULL)
    	{
    		memcpy(pRxBuffer, tmp, wTxLength);
    	}
    	*pRxLength = wTxLength;
    }
    //dump(-1, pRxBuffer, wTxLength);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_SetConfig(
                                phbalReg_RpiSpi_DataParams_t * pDataParams,
                                uint16_t wConfig,
                                uint16_t wValue
                                )
{
    switch (wConfig)
    {

    case PHBAL_REG_CONFIG_HAL_HW_TYPE:
        if((wValue != PHBAL_REG_HAL_HW_RC523))
        {
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_BAL);
        }
        pDataParams->bHalType = (uint8_t)wValue;
        break;

    default:
        return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

phStatus_t phbalReg_RpiSpi_GetConfig(
                                phbalReg_RpiSpi_DataParams_t * pDataParams,
                                uint16_t wConfig,
                                uint16_t * pValue
                                )
{
    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
}

//Ugly but needed for WiringPi
static phbalReg_RpiSpi_DataParams_t* pLocalDataParams;
static void local_callback()
{
	if(pLocalDataParams->callback != NULL)
	{
		pLocalDataParams->callback(pLocalDataParams->pUserData);
	}
}

phStatus_t phbalReg_RpiSpi_SetInterruptCallback(
												phbalReg_RpiSpi_DataParams_t * pDataParams,
												void (*callback)(void*),
												void* pUserData
											)
{
	pDataParams->callback = callback;
	pDataParams->pUserData = pUserData;

	if( callback != NULL )
	{
		pLocalDataParams = pDataParams;
		wiringPiISR(PIN_IRQ, INT_EDGE_RISING, local_callback);
	}
	else
	{
		wiringPiISR(PIN_IRQ, INT_EDGE_SETUP, NULL);
	}
	return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PHBAL_REG_RPI_SPI */

