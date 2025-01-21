#include "cmdhf14afmcos.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"  // command_t
#include "commonutil.h" // ARRAYLEN
#include "comms.h"      // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"

#include "cmdhf14a.h" // ExchangeAPDU14a

#include "iso7816/iso7816core.h"
#include "emv/emvcore.h"
#include "ui.h"
#include "crc16.h"
#include "util_posix.h" // msclock
#include "aidsearch.h"
#include "cliparser.h"
#include "protocols.h"          // definitions of ISO14A/7816 protocol, MAGIC_GEN_1A
#include "iso7816/apduinfo.h"   // GetAPDUCodeDescription
#include "cmdnfc.h"             // print_type4_cc_info
#include "fileutils.h"          // saveFile
#include "atrs.h"               // getATRinfo

#include "preferences.h" // get/set device debug level


static int CmdHelp(const char *Cmd);

static const char *get_uid_type(iso14a_card_select_t *card) {

    static char s[60] = {0};
    memset(s, 0, sizeof(s));

    switch (card->uidlen) {
        case 4: {
            if (card->uid[0] == 0x08) {
                sprintf(s, " ( RID - random ID )");
            } else if ((card->uid[0] & 0xF) == 0xF) {
                sprintf(s, " ( FNUID, fixed, non-unique ID )");
            } else if (card->uid[0] == 0x88) {
                sprintf(s, " ( Cascade tag - not final )");
            } else if (card->uid[0] == 0xF8) {
                sprintf(s, " ( RFU )");
            } else {
                sprintf(s, " ( ONUID, re-used )");
            }
            break;
        }
        case 7:  {
            sprintf(s, " ( double )");
            break;
        }
        case 10: {
            sprintf(s, " ( triple )");
            break;
        }
        default:
            break;
    }
    return s;
}


int CmdHF14AFMCOSSim(const char *Cmd)
{
    return PM3_ESOFT;
}

int SelectAndRead(const char sFileName[], const char sSelectCmd[], const char sReadCmd[], bool activateField, bool keepFieldOn, uint8_t *response, size_t szResponseMax, int *szResponse)
{

    uint8_t bufAPDU[80] = {0};
    int szAPDU = 0;

    uint16_t sw = 0;
    int ret = 0;

    param_gethex_to_eol(sSelectCmd, 0, bufAPDU, sizeof(bufAPDU), &szAPDU);
    APDU_t decoded_APDU;
    if (APDUDecode(bufAPDU, szAPDU, &decoded_APDU) == 0)
        APDUPrint(decoded_APDU);
    else
        PrintAndLogEx(WARNING, "SELECT: can't decode APDU.");
    ret = ExchangeAPDU14a(bufAPDU, szAPDU, activateField, keepFieldOn, response, szResponseMax, szResponse);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "SELECT %s: error %d", sFileName, ret);
        DropField();
        return ret;
    }

    sw = get_sw(response, *szResponse);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "SELECT %s: card returned error (%04x - %s).", sFileName, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "SELECT %s: success");
    TLVPrintFromBuffer(response, (*szResponse) - 2);

    param_gethex_to_eol(sReadCmd, 0, bufAPDU, sizeof(bufAPDU), &szAPDU);
    if (APDUDecode(bufAPDU, szAPDU, &decoded_APDU) == 0)
        APDUPrint(decoded_APDU);
    else
        PrintAndLogEx(WARNING, "READ: can't decode APDU.");
    ret = ExchangeAPDU14a(bufAPDU, szAPDU, activateField, keepFieldOn, response, szResponseMax, szResponse);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "READ %s: error %d", sFileName, ret);
        DropField();
        return ret;
    }

    sw = get_sw(response, *szResponse);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "READ %s: card returned error (%04x - %s).", sFileName, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "READ %s: success");
    PrintAndLogEx(NORMAL, "");
    print_buffer(response, *szResponse, 1);
    PrintAndLogEx(INFO, "--- " _CYAN_("READ %s") " ----------------", sFileName);
    return PM3_SUCCESS;
}


int CmdHF14AFMCOSInfo(const char *Cmd)
{
    bool verbose = true;
    // bool do_nack_test = false;
    // bool do_aid_search = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a fmcos info",
                  "This command makes more extensive tests against a ZJZY ISO14443a-FMCOS tag in order to collect information",
                  "hf 14a fmcos -v -> shows full information about the card\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",   "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    verbose = arg_get_lit(ctx, 1);
    // do_nack_test = arg_get_lit(ctx, 2);
    // do_aid_search = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        DropField();
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        DropField();
        return select_status;
    }

    PrintAndLogEx(NORMAL, "");

    if (select_status == 3) {
        PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");

        if (verbose) {
            PrintAndLogEx(SUCCESS, "ATQA: %02X %02X", card.atqa[1], card.atqa[0]);
        }

        DropField();
        return select_status;
    }

    PrintAndLogEx(INFO, "---------- " _CYAN_("ISO14443-A Information") " ----------");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s") " %s", sprint_hex(card.uid, card.uidlen), get_uid_type(&card));
    PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), card.atqa[1], card.atqa[0]);
    PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02X [%" PRIu64 "]"), card.sak, select_status);

    bool ActivateField = true;


    uint8_t bufAPDU[80] = {0};
    int szAPDU = 0;
    uint8_t response[1024] = {0};
    int szResponse = 0;
    uint16_t sw = 0;

    param_gethex_to_eol("00A4 0000 02 7F03", 0, bufAPDU, sizeof(bufAPDU), &szAPDU);
    APDU_t decoded_APDU;
    if (APDUDecode(bufAPDU, szAPDU, &decoded_APDU) == 0)
        APDUPrint(decoded_APDU);
    else
        PrintAndLogEx(WARNING, "SELECT 7F03: can't decode APDU.");

    int ret = ExchangeAPDU14a(bufAPDU, szAPDU, ActivateField, true, response, sizeof response, &szResponse);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "SELECT 7F03: error %d", ret);
        DropField();
        return ret;
    }

    sw = get_sw(response, szResponse);
    // param_gethex_to_eol("D5FDD4AAD6C7BBDBD2D7CDA81501", 0, AID, sizeof AID, &szAID);

    uint8_t sw1 = (uint8_t)(sw >> 8);
    uint8_t sw2 = (uint8_t)(0xff & sw);
    if (sw == ISO7816_OK || sw == ISO7816_INVALID_DF || sw == ISO7816_FILE_TERMINATED) {
        if (sw == ISO7816_OK) {
            if (verbose)
                PrintAndLogEx(SUCCESS, "Application " _CYAN_("7F03") " ( " _GREEN_("ok") " )");
        } else {
            if (verbose)
                PrintAndLogEx(WARNING, "Application " _CYAN_("7F03") " ( " _RED_("blocked") " )");
        }
        if (verbose)
            PrintAndLogEx(INFO, "----------------- " _CYAN_("SELECT AID") " -----------------");
    } else {
        PrintAndLogEx(FAILED, "SELECT AID " _RED_("FAILED") ": %02X %02X", sw1, sw2);
        DropField();
        return PM3_ESOFT;
    }

    ActivateField = false; // avoid resetting tag

    SelectAndRead("7F03/0001", "00A4 0000 02 0001", "00B0 0000 40", ActivateField, true, response, sizeof response, &szResponse);
    SelectAndRead("7F03/00015", "00A4 0000 02 0015", "00B0 0000 60", ActivateField, true, response, sizeof response, &szResponse);
    SelectAndRead("7F03/00015", "00A4 0000 02 0016", "00B0 0000 60", ActivateField, true, response, sizeof response, &szResponse);
    SelectAndRead("7F03/00015", "00A4 0000 02 0019", "00B0 0000 40", ActivateField, true, response, sizeof response, &szResponse);
    DropField();
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,              AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,              IfPm3Iso14443a,  "---------------------- " _CYAN_("Operations") " ---------------------"},
    {"info",        CmdHF14AFMCOSInfo,    IfPm3Iso14443a,  "Tag information"},
    {"sim",         CmdHF14AFMCOSSim,     IfPm3Iso14443a,  "Simulate ISO 14443-a tag"},
    // {"list",        CmdHF14AList,         AlwaysAvailable, "List ISO 14443-a history"},
    // {"antifuzz",    CmdHF14AAntiFuzz,     IfPm3Iso14443a,  "Fuzzing the anticollision phase.  Warning! Readers may react strange"},
    // {"config",      CmdHf14AConfig,       IfPm3Iso14443a,  "Configure 14a settings (use with caution)"},
    // {"cuids",       CmdHF14ACUIDs,        IfPm3Iso14443a,  "Collect n>0 ISO14443-a UIDs in one go"},
    // {"simaid",      CmdHF14AAIDSim,       IfPm3Iso14443a,  "Simulate ISO 14443-a AID Selection"},
    // {"sniff",       CmdHF14ASniff,        IfPm3Iso14443a,  "sniff ISO 14443-a traffic"},
    // {"raw",         CmdHF14ACmdRaw,       IfPm3Iso14443a,  "Send raw hex data to tag"},
    // {"reader",      CmdHF14AReader,       IfPm3Iso14443a,  "Act like an ISO14443-a reader"},
    // {"-----------", CmdHelp,              IfPm3Iso14443a,  "------------------------- " _CYAN_("APDU") " -------------------------"},
    // {"apdu",        CmdHF14AAPDU,         IfPm3Iso14443a,  "Send ISO 14443-4 APDU to tag"},
    // {"apdufind",    CmdHf14AFindapdu,     IfPm3Iso14443a,  "Enumerate APDUs - CLA/INS/P1P2"},
    // {"chaining",    CmdHF14AChaining,     IfPm3Iso14443a,  "Control ISO 14443-4 input chaining"},
    // {"-----------", CmdHelp,              IfPm3Iso14443a,  "------------------------- " _CYAN_("NDEF") " -------------------------"},
    // {"ndefformat",  CmdHF14ANdefFormat,   IfPm3Iso14443a,  "Format ISO 14443-A as NFC Type 4 tag"},
    // {"ndefread",    CmdHF14ANdefRead,     IfPm3Iso14443a,  "Read an NDEF file from ISO 14443-A Type 4 tag"},
    // {"ndefwrite",   CmdHF14ANdefWrite,    IfPm3Iso14443a,  "Write NDEF records to ISO 14443-A tag"},
    {NULL, NULL, NULL, NULL}
};

int CmdHF14AFMCOS(const char *Cmd)
{
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
    // return PM3_ESOFT;
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
