#ifndef __FMCOS_H
#define __FMCOS_H

#include "common.h"
#include "mifare.h" // struct
#include "pm3_cmd.h"
#include "crc16.h" // compute_crc

void GenerateFMCOSResponse(uint8_t *receivedCmd, int receivedCmdLen, tag_response_info_t *resp, int headerOffset);
void PrepareDynamicResponse(uint8_t *receivedCmd, int receivedCmdLen, tag_response_info_t *resp);
void SimulateFMCOSTag(uint8_t *uid,
                      uint8_t *iRATs, size_t irats_len);
#endif /* __FMCOS_H */
