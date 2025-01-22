#ifndef __FMCOS_H
#define __FMCOS_H

#include "common.h"
#include "mifare.h" // struct
#include "pm3_cmd.h"
#include "crc16.h" // compute_crc

#define FMCOS_RESPONSE_BUFFER_SIZE 512

// iEF == 0000: SELECT DF
// iEF == FFFF: DF name
typedef struct
{
    uint16_t iDF;
    uint16_t iEF;
    uint16_t checkSum;
    uint16_t szData;
    uint8_t bData[];
} PACKED fmcos_ef; // bData will not be included in sizeof

typedef struct {
    uint16_t len;
    uint8_t *data;
} fmcos_resp;

void FMCOSEmlMemAdd(fmcos_ef *ef);
void FMCOSEmlList(void);
fmcos_ef* FMCOSEmlGetFile(uint16_t iDF, uint16_t iEF);
fmcos_ef* FMCOSEmlGetDFByName(uint8_t *name, uint8_t szName);

void GenerateFMCOSResponse(uint8_t *receivedCmd, int receivedCmdLen, fmcos_resp *resp);
bool PrepareDynamicResponse(uint8_t *receivedCmd, int receivedCmdLen, fmcos_resp *resp);
void SimulateFMCOSTag(uint8_t *uid,
                      uint8_t *iRATs, size_t irats_len);
#endif /* __FMCOS_H */
