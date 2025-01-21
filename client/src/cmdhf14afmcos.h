
#ifndef CMDHF14AFMCOS_H__
#define CMDHF14AFMCOS_H__

#include "common.h"
#include "pm3_cmd.h" //hf14a_config
#include "mifare.h" // structs


int FMCOSEmlMemClr(void);
int FMCOSEmlMemAdd(uint16_t iDF, uint16_t iEF, uint8_t szData, uint8_t *bData);
int CmdHF14AFMCOS(const char *Cmd);
int CmdHF14AFMCOSSim(const char *Cmd);
int CmdHF14AFMCOSInfo(const char *Cmd);
int SelectAndRead(const char sFileName[], const char sSelectCmd[], const char sReadCmd[], bool activateField, bool keepFieldOn, uint8_t *response, size_t szResponseMax, int *szResponse);
#endif
