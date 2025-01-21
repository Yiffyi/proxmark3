#include "fmcos.h"
#include "iso14443a.h"

#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "protocols.h"
#include "dbprint.h"

// Increased the buffer size to allow for more complex responses
#define DYNAMIC_RESPONSE_BUFFER2_SIZE 512
#define DYNAMIC_MODULATION_BUFFER2_SIZE 1536
#define DYNAMIC_RESPONSE_BUFFER_SIZE 64
#define DYNAMIC_MODULATION_BUFFER_SIZE 512

#define STATE_NONE 0
#define STATE_HALTED 5
#define STATE_WUPA 6
#define STATE_AUTH 7

const char DF_7F03_AID[] = {
    0xD5, 0xFD, 0xD4, 0xAA, 0xD6, 0xC7, 0xBB, 0xDB, 0xD2, 0xD7, 0xCD, 0xA8, 0x15, 0x01};

const uint8_t DF_7F03_RESPONSE[] = {
    0x6F, 0x16, 0x84, 0x0E, 0xD5, 0xFD, 0xD4, 0xAA, 0xD6, 0xC7, 0xBB, 0xDB, 0xD2, 0xD7, 0xCD, 0xA8, 0x15, 0x01, 0xA5, 0x04, 0x9F, 0x08, 0x01, 0x02, 0x90, 0x00
};

const uint8_t DF_3F00_RESPONSE[] = {
    0x6F, 0x15, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0xA5, 0x03, 0x88, 0x01, 0x01, 0x90, 0x00
};

void GenerateFMCOSResponse(uint8_t *receivedCmd, int receivedCmdLen, tag_response_info_t *resp, int headerOffset)
{

    switch (receivedCmd[3])
    { // APDU Class Byte
      // receivedCmd in this case is expecting to structured with a CID, then the APDU command for SelectFile
      // | IBlock (CID) | CID | APDU Command | CRC |

    case 0xA4:
    { // SELECT FILE
        // Select File AID uses the following format for GlobalPlatform
        //
        // | 00 | A4 | 04/00 | 00 | xx | AID | 00 |
        // xx in this case is len of the AID value in hex

        // aid len is found as a hex value in receivedCmd[6] (Index Starts at 0)
        int aidLen = receivedCmd[6];
        uint8_t *receivedAid = &receivedCmd[7];

        Dbprintf("Received AID (%d):", aidLen);
        Dbhexdump(aidLen, receivedAid, false);

        if (receivedCmd[4] == 0x00 && aidLen == 2)
        {
            if (receivedAid[0] == 0x7F && receivedAid[1] == 0x03)
            {
                // SELECT 7F03: DF
                memcpy(resp->response + headerOffset, DF_7F03_RESPONSE, sizeof DF_7F03_RESPONSE);
                resp->response_n = sizeof DF_7F03_RESPONSE + headerOffset;
                return;
            }
            else if (receivedAid[0] == 0x3F && receivedAid[1] == 0x00)
            {
                memcpy(resp->response + headerOffset, DF_3F00_RESPONSE, sizeof DF_3F00_RESPONSE);
                resp->response_n = sizeof DF_3F00_RESPONSE + headerOffset;
                return;
            }
        }
        else if (receivedCmd[4] == 0x04 && aidLen == sizeof DF_7F03_AID && memcmp(DF_7F03_AID, receivedAid, aidLen) == 0)
        {
            memcpy(resp->response + headerOffset, DF_7F03_RESPONSE, sizeof DF_7F03_RESPONSE);
            resp->response_n = sizeof DF_7F03_RESPONSE + headerOffset;
            return;
        }
        // Any other SELECT FILE command will return with a Not Found
        resp->response[headerOffset] = 0x6A;
        resp->response[headerOffset + 1] = 0x82;
        resp->response_n = headerOffset + 2;
    }
    break;
    default:
    {
        // Any other non-listed command
        // Respond Not Found
        resp->response[headerOffset] = 0x6A;
        resp->response[headerOffset + 1] = 0x82;
        resp->response_n = headerOffset + 2;
    }
    }
    return;
}

void PrepareDynamicResponse(uint8_t *receivedCmd, int receivedCmdLen, tag_response_info_t *resp)
{

    // clear old dynamic responses
    resp->response_n = 0;
    resp->modulation_n = 0;

    // Check for ISO 14443A-4 compliant commands, look at left nibble
    switch (receivedCmd[0])
    {
    case 0x02:
    case 0x03:
    { // IBlock (command no CID)
        resp->response[0] = receivedCmd[0];
        resp->response[1] = 0x90;
        resp->response[2] = 0x00;
        resp->response_n = 3;
        GenerateFMCOSResponse(receivedCmd, receivedCmdLen, resp, 1);
    }
    break;
    case 0x0B:
    case 0x0A:
    { // IBlock (command CID)
        resp->response[0] = receivedCmd[0];
        resp->response[1] = receivedCmd[1];
        resp->response[2] = 0x90;
        resp->response[3] = 0x00;
        resp->response_n = 4;
        GenerateFMCOSResponse(receivedCmd, receivedCmdLen, resp, 2);
    }
    break;

    case 0x1A:
    case 0x1B:
    { // Chaining command
        resp->response[0] = 0xaa | ((receivedCmd[0]) & 1);
        resp->response_n = 2;
    }
    break;

    case 0xAA:
    case 0xBB:
    {
        resp->response[0] = receivedCmd[0] ^ 0x11;
        resp->response_n = 2;
    }
    break;

    case 0xBA:
    { // ping / pong
        resp->response[0] = 0xAB;
        resp->response[1] = 0x00;
        resp->response_n = 2;
    }
    break;

    case 0xCA:
    case 0xC2:
    { // Readers sends deselect command
        resp->response[0] = 0xCA;
        resp->response[1] = 0x00;
        resp->response_n = 2;
    }
    break;

    default:
    {
        if (g_dbglevel >= DBG_DEBUG)
        {
            Dbprintf("Received unknown command (len=%d):", receivedCmdLen);
            Dbhexdump(receivedCmdLen, receivedCmd, false);
        }
        // Do not respond
        resp->response_n = 0;
        // order = ORDER_NONE; // back to work state
    }
    break;
    }


    if (resp->response_n > 0)
    {
        // Copy the CID from the reader query???
        // resp->response[1] = receivedCmd[1];

        // Add CRC bytes, always used in ISO 14443A-4 compliant cards
        AddCrc14A(resp->response, resp->response_n);
        resp->response_n += 2;

        if (prepare_tag_modulation(resp, DYNAMIC_MODULATION_BUFFER_SIZE) == false)
        {
            if (g_dbglevel >= DBG_DEBUG)
                DbpString("Error preparing tag response");
        }
    }
}

void SimulateFMCOSTag(uint8_t *uid,
                      uint8_t *iRATs, size_t irats_len)
{
    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = {0x00, 0x00, 0x00};
    uint8_t tearings[3] = {0xbd, 0xbd, 0xbd};
    uint8_t pages = 0;

    // command buffers
    int receivedCmdLen = 0;
    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = {0x00};

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    uint8_t *dynamic_response_buffer2 = BigBuf_calloc(DYNAMIC_RESPONSE_BUFFER2_SIZE);
    uint8_t *dynamic_modulation_buffer2 = BigBuf_calloc(DYNAMIC_MODULATION_BUFFER2_SIZE);
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer2,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer2,
        .modulation_n = 0};

    uint8_t tagType = 4;
    uint16_t flags = 0;
    FLAG_SET_UID_IN_DATA(flags, 4);
    flags |= FLAG_RATS_IN_DATA;
    if (SimulateIso14443aInit(tagType, flags, uid, iRATs, irats_len, &responses, &cuid, counters, tearings, &pages) == false)
    {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
    iso14a_set_timeout(201400); // 106 * 19ms default *100?

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    int retval = 0;
    int cmdsRecvd = 0;
    bool odd_reply = true;
    bool finished = false;
    while (finished == false)
    {
        // BUTTON_PRESS check done in GetIso14443aCommandFromReader
        WDT_HIT();
        tag_response_info_t *p_response = NULL;

        // Clean receive command buffer
        if (GetIso14443aCommandFromReader(receivedCmd, sizeof(receivedCmd), receivedCmdPar, &receivedCmdLen) == false)
        {
            Dbprintf("Emulator stopped. Trace length: %d ", BigBuf_get_traceLen());
            retval = PM3_EOPABORTED;
            break;
        }

        tUart14a *Uart = GetUart14a();

        LogTrace(receivedCmd, Uart->len, Uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart->parity, true);

        if (receivedCmd[0] == ISO14443A_CMD_REQA && receivedCmdLen == 1)
        { // Received a REQUEST, but in HALTED, skip
            odd_reply = !odd_reply;
            if (odd_reply)
            {
                p_response = &responses[RESP_INDEX_ATQA];
            }
        }
        else if (receivedCmd[0] == ISO14443A_CMD_WUPA && receivedCmdLen == 1)
        { // Received a WAKEUP
            p_response = &responses[RESP_INDEX_ATQA];
        }
        else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmdLen == 2)
        { // Received request for UID (cascade 1)
            p_response = &responses[RESP_INDEX_UIDC1];
        }
        else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmdLen == 2)
        { // Received request for UID (cascade 2)
            p_response = &responses[RESP_INDEX_UIDC2];
        }
        else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmdLen == 2)
        { // Received request for UID (cascade 3)
            p_response = &responses[RESP_INDEX_UIDC3];
        }
        else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmdLen == 9)
        { // Received a SELECT (cascade 1)
            p_response = &responses[RESP_INDEX_SAKC1];
        }
        else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmdLen == 9)
        { // Received a SELECT (cascade 2)
            p_response = &responses[RESP_INDEX_SAKC2];
        }
        else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmdLen == 9)
        { // Received a SELECT (cascade 3)
            p_response = &responses[RESP_INDEX_SAKC3];
        }
        else if (receivedCmd[0] == ISO14443A_CMD_PPS)
        {
            p_response = &responses[RESP_INDEX_PPS];
        }
        else if (receivedCmd[0] == ISO14443A_CMD_HALT && receivedCmdLen == 4)
        { // Received a HALT
            p_response = NULL;
            // order = ORDER_HALTED;
        }
        else if (receivedCmd[0] == ISO14443A_CMD_RATS && receivedCmdLen == 4)
        { // Received a RATS request
            p_response = &responses[RESP_INDEX_RATS];
        }
        else
        {
            PrepareDynamicResponse(receivedCmd, receivedCmdLen, &dynamic_response_info);
            p_response = &dynamic_response_info;
        }
        cmdsRecvd++;
        // Send response
        EmSendPrecompiledCmd(p_response);
    }

    switch_off();

    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED)
    {
        //        Dbprintf("-[ Wake ups after halt  [%d]", happened);
        //        Dbprintf("-[ Messages after halt  [%d]", happened2);
        Dbprintf("-[ Num of received cmd  [%d]", cmdsRecvd);
    }

    reply_ng(CMD_HF_ISO14443A_FMCOS_SIMULATE, retval, NULL, 0);
}