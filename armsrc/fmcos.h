#ifndef __FMCOS_H
#define __FMCOS_H

#include "common.h"
#include "mifare.h" // struct
#include "pm3_cmd.h"
#include "crc16.h" // compute_crc

void SimulateFMCOSTag(uint8_t tagType, uint8_t *uid,
                      uint8_t *iRATs, size_t irats_len);
#endif /* __FMCOS_H */
