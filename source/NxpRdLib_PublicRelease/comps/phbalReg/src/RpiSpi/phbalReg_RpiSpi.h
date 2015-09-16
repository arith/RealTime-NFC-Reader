/**
 * \file phbalReg_RpiSpi.h
 * \author Donatien Garnier
 */

#ifndef PHBALREG_RPISPI_H
#define PHBALREG_RPISPI_H

#include <ph_Status.h>

phStatus_t phbalReg_RpiSpi_GetPortList(
    phbalReg_RpiSpi_DataParams_t * pDataParams,
    uint16_t wPortBufSize,
    uint8_t * pPortNames,
    uint16_t * pNumOfPorts
    );

phStatus_t phbalReg_RpiSpi_SetPort(
                            phbalReg_RpiSpi_DataParams_t * pDataParams,
                            uint8_t * pPortName
                            );

phStatus_t phbalReg_RpiSpi_OpenPort(
                                  phbalReg_RpiSpi_DataParams_t * pDataParams
                                  );

phStatus_t phbalReg_RpiSpi_ClosePort(
                                   phbalReg_RpiSpi_DataParams_t * pDataParams
                                   );

phStatus_t phbalReg_RpiSpi_Exchange(
                                  phbalReg_RpiSpi_DataParams_t * pDataParams,
                                  uint8_t * pTxBuffer,
                                  uint16_t wTxLength,
                                  uint16_t wRxBufSize,
                                  uint8_t * pRxBuffer,
                                  uint16_t * pRxLength
                                  );

phStatus_t phbalReg_RpiSpi_SetConfig(
                                   phbalReg_RpiSpi_DataParams_t * pDataParams,
                                   uint16_t wConfig,
                                   uint16_t wValue
                                   );

phStatus_t phbalReg_RpiSpi_GetConfig(
                                   phbalReg_RpiSpi_DataParams_t * pDataParams,
                                   uint16_t wConfig,
                                   uint16_t * pValue
                                   );


phStatus_t phbalReg_RpiSpi_SetInterruptCallback(
												phbalReg_RpiSpi_DataParams_t * pDataParams,
												void (*callback)(void*),
												void* pUserData
											);



#endif /* PHBALREG_RPISPI_H */
