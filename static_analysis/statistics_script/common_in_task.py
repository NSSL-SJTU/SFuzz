# coding:utf-8
# find trace
# 25min version

# NOTICE: OUTPUT FORMAT DEFINITION

# call patch output:
# <addr> nop <0 or 1>
#   0 or 1: stand for whether the subfuction contains subsubfunctions or not, angr will not patch the call instr if it equals 1, but fuzzer will still patch no matter 0 or 1

# jmp patch output:
# <addr> jmp <target addr> [avoid excution/exit emulation addr]
#   if target addr == 0, it means this condition jump is input-data-related, so angr and fuzzer will not patch this condition jmp, however the 4th args here stands for the branch that cannot reach target function, so fuzzer will interpret this addr and when it reaches this addr it will straightly end current simulation(so that AFL will consider current input as 'uninterested'), also angr will interpret this arg and abort any state that reach this addr
#   if target addr != 0, it means this condition jump is not input-data-related, so fuzzer will patch this condition jump(while angr will not), and angr will interpret the 4th arg so that it saves much time on simulating multiple states(while fuzzer will not)
#   the 4th args here is not requisite, which means if both branch are reachable to target function, obviously we should not do anything to program

import string
import re
import os
import json
import sys

from ghidra.app.plugin.core.analysis import DefaultDataTypeManagerService
from ghidra.app.util.parser import FunctionSignatureParser

try:
    import queue as Queue
except:
    import Queue
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import PcodeBlockBasic
from ghidra.program.model.listing import Function
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlock
from ghidra.program.model.pcode import PcodeOp, Varnode, PcodeOpAST, HighSymbol
from ghidra.program.model.address import GenericAddress
import ghidra.program.model.address.GenericAddress
from ghidra.program.model.listing import Data
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import PartitionCodeSubModel
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.util.exception import DuplicateNameException
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.pcode import HighParam,HighLocal
from ghidra.program.model.scalar import Scalar
import time
import json

try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

TREE_FUNCS = """{
    "10400_D196G_result": [
        {
            "id": "0",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "1",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "httpRecvReply",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "httpRecvReply"
        },
        {
            "id": "10",
            "funcs": [
                "__getDstInfo",
                "strtok_r",
                "strcpy",
                "strncpy",
                "bzero",
                "atoi",
                "getenv",
                "strcmp"
            ],
            "top_func": "__getDstInfo"
        },
        {
            "id": "11",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "FUN_4028ffb4",
                "modelRead",
                "jsonObjectArrayLength",
                "utf8Truncate",
                "bcopy",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "12",
            "funcs": [
                "memset",
                "apps_wpsProcessM8",
                "apps_wpsDecryptData",
                "wlanWdsSetChannel",
                "_eventSendMsgId",
                "wlan5gWdsSetChannel",
                "apps_wpsSucess",
                "my_printf",
                "apps_wpsAddExt",
                "apps_wpsProcessM7",
                "gpioRead",
                "miniFsReadFile",
                "apps_wpsCreateM7",
                "apps_wpsCreateM4",
                "wlanSetSecCheck",
                "apps_wpsCreateM8",
                "_wpsSendDeauth",
                "wlan5gWdsSetBandWidth",
                "writeProFile",
                "_tWlanTask",
                "memcmp",
                "MmtAte",
                "mcbFree",
                "recvfrom",
                "apps_wpsChkAuthenticator",
                "crypto_sha256",
                "apps_wpsCreatNack",
                "wlanWpsSetPskSecret",
                "gpioWrite",
                "spliter",
                "select",
                "apps_wpsCreateM2",
                "modelRead",
                "wlanWdsSetPhyMode",
                "MmtAtePrase",
                "apps_wpsProbReqIndicate",
                "wpsDevRegister",
                "crypto_hmacSha256",
                "_wpsRecvMsg",
                "modelWrite",
                "apps_wpsEventIndicate",
                "printf",
                "rsaVerifySignByBase64EncodePublicKeyBlob",
                "apps_wpsProcessM4",
                "apps_wpsProcessM2",
                "wlanIsWpsConfigured",
                "apps_wpsProcessM5",
                "apps_addPbcInfo",
                "strlen",
                "wlan5gWdsSetPhyMode",
                "apps_wssEventIndicate",
                "readProFile",
                "apps_wpsCreateM2D",
                "apps_wpsGetTlv",
                "flashReadUID",
                "FUN_4028ffb4",
                "_wpsSetLed",
                "_chkWlanReload",
                "apps_wpsGetV2Tlv",
                "apps_wpsEncryptData",
                "apps_wpsProcessM2D",
                "wlanSwASCtoKey",
                "apps_wpsProcessM1",
                "strncpy",
                "apps_wpsReload",
                "isHwBtnTestMode",
                "apps_wpsTimer",
                "macBinToString",
                "wlStartWPSByPBC",
                "apps_wpsChkNonce",
                "apps_wpsCreateM6",
                "sprintf",
                "wlanWpsSetConfigured",
                "apps_wpsPbcOverlap",
                "wlanWpsSetSecStatus",
                "apps_wpsProcessM3",
                "crypto_dhCalcPubKey",
                "wpsProcessSoapReq",
                "_eventSendMsgVal32",
                "crypto_dhCalcSecretKey",
                "apps_wpsCreateM5",
                "setWlanReload",
                "apps_wpsSendEapFail",
                "mcbAlign",
                "_eventIndicate",
                "wlanWpsSetSsid",
                "apps_wpsCreateM3",
                "apps_wpsProcessAck",
                "apps_wpsProcessDone",
                "crypto_wpsDeriveKey",
                "bcopy",
                "readTpHead",
                "ctrlMonitorDoAction",
                "wlanWpsGetSecCfg",
                "apps_wpsSendPkt",
                "snprintf",
                "apps_wpsProcessM6",
                "apps_wpsChkPinAttack",
                "sendto",
                "os_random",
                "apps_wpsAddTlv",
                "apps_wpsGetCfg",
                "wlanWdsSetBandWidth",
                "apps_wssTaskHandler",
                "strncmp"
            ],
            "top_func": "_tWlanTask"
        },
        {
            "id": "13",
            "funcs": [
                "recvfrom",
                "bcopy",
                "FUN_4028ffb4",
                "tftpSendDetectServer",
                "tftpSendFile"
            ],
            "top_func": "tftpSendFile"
        },
        {
            "id": "14",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "15",
            "funcs": [
                "memset",
                "apps_wpsProcessM8",
                "apps_wpsDecryptData",
                "wlanWdsSetChannel",
                "_eventSendMsgId",
                "wlan5gWdsSetChannel",
                "apps_wpsSucess",
                "my_printf",
                "apps_wpsAddExt",
                "apps_wpsProcessM7",
                "gpioRead",
                "miniFsReadFile",
                "apps_wpsCreateM7",
                "apps_wpsCreateM4",
                "wlanSetSecCheck",
                "apps_wpsCreateM8",
                "_wpsSendDeauth",
                "wlan5gWdsSetBandWidth",
                "writeProFile",
                "_tWlanTask",
                "memcmp",
                "MmtAte",
                "mcbFree",
                "recvfrom",
                "apps_wpsChkAuthenticator",
                "crypto_sha256",
                "apps_wpsCreatNack",
                "wlanWpsSetPskSecret",
                "gpioWrite",
                "spliter",
                "select",
                "apps_wpsCreateM2",
                "modelRead",
                "wlanWdsSetPhyMode",
                "MmtAtePrase",
                "apps_wpsProbReqIndicate",
                "wpsDevRegister",
                "crypto_hmacSha256",
                "_wpsRecvMsg",
                "modelWrite",
                "apps_wpsEventIndicate",
                "printf",
                "rsaVerifySignByBase64EncodePublicKeyBlob",
                "apps_wpsProcessM4",
                "apps_wpsProcessM2",
                "wlanIsWpsConfigured",
                "apps_wpsProcessM5",
                "apps_addPbcInfo",
                "strlen",
                "wlan5gWdsSetPhyMode",
                "apps_wssEventIndicate",
                "readProFile",
                "apps_wpsCreateM2D",
                "apps_wpsGetTlv",
                "flashReadUID",
                "FUN_4028ffb4",
                "_wpsSetLed",
                "_chkWlanReload",
                "apps_wpsGetV2Tlv",
                "apps_wpsEncryptData",
                "apps_wpsProcessM2D",
                "wlanSwASCtoKey",
                "apps_wpsProcessM1",
                "strncpy",
                "apps_wpsReload",
                "isHwBtnTestMode",
                "apps_wpsTimer",
                "macBinToString",
                "wlStartWPSByPBC",
                "apps_wpsChkNonce",
                "apps_wpsCreateM6",
                "sprintf",
                "wlanWpsSetConfigured",
                "apps_wpsPbcOverlap",
                "wlanWpsSetSecStatus",
                "apps_wpsProcessM3",
                "crypto_dhCalcPubKey",
                "wpsProcessSoapReq",
                "_eventSendMsgVal32",
                "crypto_dhCalcSecretKey",
                "apps_wpsCreateM5",
                "setWlanReload",
                "apps_wpsSendEapFail",
                "mcbAlign",
                "_eventIndicate",
                "wlanWpsSetSsid",
                "apps_wpsCreateM3",
                "apps_wpsProcessAck",
                "apps_wpsProcessDone",
                "crypto_wpsDeriveKey",
                "bcopy",
                "readTpHead",
                "ctrlMonitorDoAction",
                "wlanWpsGetSecCfg",
                "apps_wpsSendPkt",
                "snprintf",
                "apps_wpsProcessM6",
                "apps_wpsChkPinAttack",
                "sendto",
                "os_random",
                "apps_wpsAddTlv",
                "apps_wpsGetCfg",
                "wlanWdsSetBandWidth",
                "apps_wssTaskHandler",
                "strncmp"
            ],
            "top_func": "_tWlanTask"
        },
        {
            "id": "16",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "cloudComHelloCloudRspSef",
                "FUN_4028ffb4",
                "modelRead",
                "atoi",
                "tickGet",
                "bcopy",
                "cloudComSetReconnectTime",
                "strncpy",
                "cloudComSendHelloCloudToSefError",
                "snprintf",
                "cloudComSetStopConnect",
                "jsonObjectGetInt",
                "sysClkRateGet",
                "strstr",
                "jsonObjectGetString",
                "cloudComGetConfigInfo"
            ],
            "top_func": "cloudComHelloCloudRspSef"
        },
        {
            "id": "17",
            "funcs": [
                "httpDefAuthKey",
                "logOutput",
                "jsonObjectNewObject",
                "strlen",
                "unAuthLogCleanIpv6",
                "memset",
                "httpResetContext",
                "authLoginSuccessPushInfo",
                "authLoginSuccessPushInfoIpv6",
                "jsonObjectObjectDelete",
                "strcmp",
                "jsonObjectToString",
                "nd6_get_mac_by_ip",
                "jsonObjectObjectIsNull",
                "httpChangeSession",
                "strchr",
                "memmove",
                "staMgtFindRuntimeEntryById",
                "modelDecodeSC",
                "httpProcDsMethod",
                "unAuthLogClean",
                "FUN_4028ffb4",
                "modelEncodeSC",
                "modelRead",
                "unAuthLogAdd",
                "sessionMatch",
                "tickGet",
                "httpUnAuthHandle",
                "jsonObjectAddInt",
                "httpGenAuthKey",
                "strncpy",
                "jsonObjectObjectAdd",
                "httpGenDictionary",
                "jsonObjectAddString",
                "jsonObjectFromString",
                "snprintf",
                "modelWrite",
                "httpDoAuthorize",
                "jsonObjectGetString",
                "unAuthLogOutput",
                "jsonObjectObjectGet",
                "strcpy",
                "memcmp",
                "unAuthLogAddIpv6",
                "httpGenTmpAuthKey",
                "httpDoChangePwd",
                "sessionMatchIpv6",
                "notifySecdataChanged",
                "httpProcDataSrv"
            ],
            "top_func": "httpProcDataSrv"
        },
        {
            "id": "18",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "FUN_4028ffb4",
                "modelRead",
                "jsonObjectArrayLength",
                "utf8Truncate",
                "bcopy",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "19",
            "funcs": [
                "logOutput",
                "pluginNoneTableReset",
                "utf8Truncate",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "mcbAlign",
                "strcpy",
                "strlen",
                "addUninstalledPluginToTable",
                "memset",
                "strncpy",
                "jsonObjectArrayGetIdx",
                "encodeLogSC",
                "getNotInsPluginResultHandle",
                "jsonObjectArrayLength",
                "jsonObjectGetInt",
                "mcbFree"
            ],
            "top_func": "getNotInsPluginResultHandle"
        },
        {
            "id": "2",
            "funcs": [
                "logOutput",
                "recvfrom",
                "isGlobalIpv6Addr",
                "dhcpv6cCtrlCallBk",
                "rtadvcCalIpv6Addr",
                "detectResultHandle",
                "rtadvcUpdateAddr",
                "memset",
                "bcmp",
                "rtadvcFlushAddr",
                "mcbAlign",
                "FUN_4028ffb4",
                "rtadvcHandle",
                "bcopy",
                "strncpy",
                "snprintf",
                "rtadvcFlushGateway",
                "rtadvcUpdateGateway",
                "radvcFlushDns",
                "ip6_sprintf",
                "mcbFree"
            ],
            "top_func": "rtadvcHandle"
        },
        {
            "id": "20",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "3",
            "funcs": [
                "strcpy",
                "__getZoneInfo",
                "getenv",
                "strcmp",
                "strpbrk"
            ],
            "top_func": "__getZoneInfo"
        },
        {
            "id": "4",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "FUN_4028ffb4",
                "modelRead",
                "jsonObjectArrayLength",
                "utf8Truncate",
                "bcopy",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "5",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "6",
            "funcs": [
                "recvfrom",
                "bcopy",
                "memset",
                "FUN_4028ffb4",
                "close",
                "tftpSendRequest",
                "tftpSendDetectServer",
                "tftpcDownloadFile",
                "socket",
                "bind"
            ],
            "top_func": "tftpcDownloadFile"
        },
        {
            "id": "7",
            "funcs": [
                "logOutput",
                "jsonObjectGetString",
                "mcbAlign",
                "strcpy",
                "memset",
                "strncpy",
                "modelRead",
                "checkDownloadStatus",
                "uninstallPluginReqHandle",
                "snprintf",
                "downloadProcessKickoff",
                "modelWrite",
                "mcbFree"
            ],
            "top_func": "uninstallPluginReqHandle"
        },
        {
            "id": "8",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "httpRecvReply",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "httpRecvReply"
        },
        {
            "id": "9",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "FUN_4028ffb4",
                "modelRead",
                "jsonObjectArrayLength",
                "utf8Truncate",
                "bcopy",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        }
    ],
    "10400_wdr7620_result": [
        {
            "id": "0",
            "funcs": [
                "jsonObjectGetString",
                "FUN_40330448",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330448"
        },
        {
            "id": "1",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "wlan5gWdsSetPhyMode",
                "_eventSendMsgVal32",
                "wlanWdsSetChannel",
                "_eventSendMsgId",
                "apps_wssEventIndicate",
                "spliter",
                "readProFile",
                "wlan5gWdsSetChannel",
                "mcbAlign",
                "flashReadUID",
                "select",
                "FUN_403096f4",
                "modelRead",
                "wlanWdsSetPhyMode",
                "_chkWlanReload",
                "MmtAtePrase",
                "_eventIndicate",
                "memcpy",
                "my_printf",
                "wlanSwASCtoKey",
                "readTpHead",
                "strncpy",
                "ctrlMonitorDoAction",
                "snprintf",
                "macBinToString",
                "miniFsReadFile",
                "printf",
                "sendto",
                "sprintf",
                "rsaVerifySignByBase64EncodePublicKeyBlob",
                "wlan5gWdsSetBandWidth",
                "wlanWdsSetBandWidth",
                "apps_wssTaskHandler",
                "writeProFile",
                "memcmp",
                "strncmp",
                "MmtAte",
                "mcbFree"
            ],
            "top_func": "FUN_403096f4"
        },
        {
            "id": "10",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "11",
            "funcs": [
                "__getDstInfo",
                "strtok_r",
                "strcpy",
                "strncpy",
                "bzero",
                "atoi",
                "getenv",
                "strcmp"
            ],
            "top_func": "__getDstInfo"
        },
        {
            "id": "12",
            "funcs": [
                "recvfrom",
                "memcpy",
                "tftpSendDetectServer",
                "tftpSendFile"
            ],
            "top_func": "tftpSendFile"
        },
        {
            "id": "13",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "14",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "15",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "FUN_403096f4",
                "select",
                "apps_wssTaskHandler",
                "MmtAtePrase",
                "_chkWlanReload",
                "_eventIndicate",
                "strncmp",
                "memcpy",
                "MmtAte",
                "spliter"
            ],
            "top_func": "FUN_403096f4"
        },
        {
            "id": "16",
            "funcs": [
                "logOutput",
                "pluginNoneTableReset",
                "utf8Truncate",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "mcbAlign",
                "strcpy",
                "strlen",
                "addUninstalledPluginToTable",
                "memset",
                "strncpy",
                "jsonObjectArrayGetIdx",
                "encodeLogSC",
                "getNotInsPluginResultHandle",
                "jsonObjectArrayLength",
                "jsonObjectGetInt",
                "mcbFree"
            ],
            "top_func": "getNotInsPluginResultHandle"
        },
        {
            "id": "17",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "18",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "memset",
                "strncpy",
                "FUN_404ae4c8",
                "memcmp",
                "recvn"
            ],
            "top_func": "FUN_404ae4c8"
        },
        {
            "id": "19",
            "funcs": [
                "logOutput",
                "jsonObjectGetString",
                "mcbAlign",
                "strcpy",
                "memset",
                "strncpy",
                "modelRead",
                "checkDownloadStatus",
                "uninstallPluginReqHandle",
                "snprintf",
                "downloadProcessKickoff",
                "modelWrite",
                "mcbFree"
            ],
            "top_func": "uninstallPluginReqHandle"
        },
        {
            "id": "2",
            "funcs": [
                "FUN_403302b4",
                "jsonObjectGetString",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_403302b4"
        },
        {
            "id": "20",
            "funcs": [
                "jsonObjectGetString",
                "FUN_40330448",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330448"
        },
        {
            "id": "21",
            "funcs": [
                "httpDefAuthKey",
                "logOutput",
                "jsonObjectNewObject",
                "jsonObjectNextSubObject",
                "httpGetPassword",
                "strlen",
                "httpCleanSessionClient",
                "memset",
                "strcmp",
                "httpChangeSession",
                "strchr",
                "modelDecodeSC",
                "httpCleanSessionClientIpv6",
                "doActionToModel",
                "modelRead",
                "jsonObjectAddIntByStr",
                "jsonObjectAddInt",
                "strncpy",
                "FUN_404c9fb0",
                "modelWrite",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectIsObject",
                "strcpy",
                "httpDoChangePwd",
                "notifySecdataChanged"
            ],
            "top_func": "FUN_404c9fb0"
        },
        {
            "id": "22",
            "funcs": [
                "FUN_403302b4",
                "jsonObjectGetString",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_403302b4"
        },
        {
            "id": "23",
            "funcs": [
                "logOutput",
                "recvfrom",
                "isGlobalIpv6Addr",
                "dhcpv6cCtrlCallBk",
                "rtadvcCalIpv6Addr",
                "detectResultHandle",
                "rtadvcUpdateAddr",
                "memset",
                "bcmp",
                "rtadvcFlushAddr",
                "mcbAlign",
                "memcpy",
                "strncpy",
                "snprintf",
                "rtadvcFlushGateway",
                "FUN_4032b61c",
                "rtadvcUpdateGateway",
                "radvcFlushDns",
                "ip6_sprintf",
                "mcbFree"
            ],
            "top_func": "FUN_4032b61c"
        },
        {
            "id": "24",
            "funcs": [
                "logOutput",
                "get2ndDomain",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "saveUseState",
                "strlen",
                "memset",
                "strncpy",
                "FUN_403244b8",
                "commonResultHandle",
                "jsonObjectArrayGetIdx",
                "modelRead",
                "jsonObjectArrayLength",
                "memcmp",
                "mcbMalloc",
                "memcpy",
                "macStr2Eth",
                "mcbFree"
            ],
            "top_func": "FUN_403244b8"
        },
        {
            "id": "25",
            "funcs": [
                "logOutput",
                "copy_msg_element",
                "protocol_handler",
                "get_node",
                "recvfrom",
                "FUN_404d12b8",
                "memset",
                "strncpy",
                "parse_msg_element",
                "get_new_node",
                "parse_advertisement_frame",
                "csum",
                "send_advertisement_frame",
                "memcmp",
                "memcpy",
                "parse_discovery_frame",
                "ms_idle_handler"
            ],
            "top_func": "FUN_404d12b8"
        },
        {
            "id": "26",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "27",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "28",
            "funcs": [
                "httpDefAuthKey",
                "logOutput",
                "jsonObjectNewObject",
                "strlen",
                "unAuthLogCleanIpv6",
                "memset",
                "httpResetContext",
                "authLoginSuccessPushInfo",
                "authLoginSuccessPushInfoIpv6",
                "jsonObjectObjectDelete",
                "strcmp",
                "jsonObjectToString",
                "nd6_get_mac_by_ip",
                "jsonObjectObjectIsNull",
                "httpChangeSession",
                "strchr",
                "memmove",
                "staMgtFindRuntimeEntryById",
                "modelDecodeSC",
                "httpProcDsMethod",
                "unAuthLogClean",
                "modelEncodeSC",
                "modelRead",
                "memcpy",
                "sessionMatch",
                "tickGet",
                "unAuthLogAdd",
                "httpUnAuthHandle",
                "jsonObjectAddInt",
                "httpGenAuthKey",
                "strncpy",
                "jsonObjectObjectAdd",
                "httpGenDictionary",
                "jsonObjectAddString",
                "jsonObjectFromString",
                "snprintf",
                "modelWrite",
                "httpDoAuthorize",
                "jsonObjectGetString",
                "unAuthLogOutput",
                "jsonObjectObjectGet",
                "strcpy",
                "memcmp",
                "unAuthLogAddIpv6",
                "httpGenTmpAuthKey",
                "httpDoChangePwd",
                "sessionMatchIpv6",
                "notifySecdataChanged",
                "httpProcDataSrv"
            ],
            "top_func": "httpProcDataSrv"
        },
        {
            "id": "3",
            "funcs": [
                "recvfrom",
                "logOutput",
                "strstr",
                "printf",
                "strchr",
                "strlen",
                "memset",
                "strncpy",
                "ssdpSendReply",
                "miniUPnPSSDPHandle",
                "snprintf",
                "strncasecmp",
                "strncopy",
                "memcpy",
                "ssdpFlag"
            ],
            "top_func": "miniUPnPSSDPHandle"
        },
        {
            "id": "4",
            "funcs": [
                "strcpy",
                "__getZoneInfo",
                "getenv",
                "strcmp",
                "strpbrk"
            ],
            "top_func": "__getZoneInfo"
        },
        {
            "id": "5",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "6",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "7",
            "funcs": [
                "recvfrom",
                "memcpy",
                "memset",
                "close",
                "tftpSendRequest",
                "tftpSendDetectServer",
                "tftpcDownloadFile",
                "socket",
                "bind"
            ],
            "top_func": "tftpcDownloadFile"
        },
        {
            "id": "8",
            "funcs": [
                "cloudComHelloCloudRspSef",
                "logOutput",
                "strstr",
                "jsonObjectGetString",
                "strlen",
                "cloudComSetReconnectTime",
                "memset",
                "strncpy",
                "cloudComSendHelloCloudToSefError",
                "modelRead",
                "sysClkRateGet",
                "atoi",
                "snprintf",
                "cloudComSetStopConnect",
                "memcpy",
                "jsonObjectGetInt",
                "tickGet",
                "cloudComGetConfigInfo"
            ],
            "top_func": "cloudComHelloCloudRspSef"
        },
        {
            "id": "9",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "memset",
                "strncpy",
                "FUN_404ae4c8",
                "memcmp",
                "recvn"
            ],
            "top_func": "FUN_404ae4c8"
        }
    ],
    "10400_wdr7660_result": [
        {
            "id": "0",
            "funcs": [
                "recvfrom",
                "logOutput",
                "strstr",
                "printf",
                "strchr",
                "strlen",
                "memset",
                "strncpy",
                "ssdpSendReply",
                "miniUPnPSSDPHandle",
                "snprintf",
                "strncasecmp",
                "strncopy",
                "memcpy",
                "ssdpFlag"
            ],
            "top_func": "miniUPnPSSDPHandle"
        },
        {
            "id": "1",
            "funcs": [
                "strcpy",
                "__getZoneInfo",
                "getenv",
                "strcmp",
                "strpbrk"
            ],
            "top_func": "__getZoneInfo"
        },
        {
            "id": "10",
            "funcs": [
                "__getDstInfo",
                "strtok_r",
                "strcpy",
                "strncpy",
                "bzero",
                "atoi",
                "getenv",
                "strcmp"
            ],
            "top_func": "__getDstInfo"
        },
        {
            "id": "11",
            "funcs": [
                "recvfrom",
                "memcpy",
                "tftpSendDetectServer",
                "tftpSendFile"
            ],
            "top_func": "tftpSendFile"
        },
        {
            "id": "12",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "13",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "14",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "httpRecvReply",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "httpRecvReply"
        },
        {
            "id": "15",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "16",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "17",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "18",
            "funcs": [
                "jsonObjectGetString",
                "strlen",
                "memset",
                "hostWds5gJsonToBin",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "hostWds5gJsonToBin"
        },
        {
            "id": "19",
            "funcs": [
                "logOutput",
                "pluginNoneTableReset",
                "utf8Truncate",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "mcbAlign",
                "strcpy",
                "strlen",
                "addUninstalledPluginToTable",
                "memset",
                "strncpy",
                "jsonObjectArrayGetIdx",
                "encodeLogSC",
                "getNotInsPluginResultHandle",
                "jsonObjectArrayLength",
                "jsonObjectGetInt",
                "mcbFree"
            ],
            "top_func": "getNotInsPluginResultHandle"
        },
        {
            "id": "2",
            "funcs": [
                "jsonObjectGetString",
                "hostWds2gJsonToBin",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "hostWds2gJsonToBin"
        },
        {
            "id": "20",
            "funcs": [
                "recvfrom",
                "logOutput",
                "isGlobalIpv6Addr",
                "dhcpv6cCtrlCallBk",
                "rtadvcCalIpv6Addr",
                "detectResultHandle",
                "rtadvcUpdateAddr",
                "memset",
                "rtadvcFlushAddr",
                "mcbAlign",
                "memcmp__1",
                "memcpy",
                "rtadvcHandle",
                "strncpy",
                "snprintf",
                "rtadvcFlushGateway",
                "rtadvcUpdateGateway",
                "radvcFlushDns",
                "ip6_sprintf",
                "mcbFree"
            ],
            "top_func": "rtadvcHandle"
        },
        {
            "id": "21",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "22",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "select",
                "apps_wssTaskHandler",
                "MmtAtePrase",
                "_chkWlanReload",
                "_tWlanTask",
                "_eventIndicate",
                "strncmp",
                "memcpy",
                "MmtAte",
                "spliter"
            ],
            "top_func": "_tWlanTask"
        },
        {
            "id": "23",
            "funcs": [
                "httpDefAuthKey",
                "logOutput",
                "jsonObjectNewObject",
                "strlen",
                "unAuthLogCleanIpv6",
                "memset",
                "httpResetContext",
                "authLoginSuccessPushInfo",
                "authLoginSuccessPushInfoIpv6",
                "jsonObjectObjectDelete",
                "strcmp",
                "jsonObjectToString",
                "nd6_get_mac_by_ip",
                "jsonObjectObjectIsNull",
                "httpChangeSession",
                "strchr",
                "memmove",
                "staMgtFindRuntimeEntryById",
                "modelDecodeSC",
                "httpProcDsMethod",
                "unAuthLogClean",
                "modelEncodeSC",
                "modelRead",
                "memcpy",
                "sessionMatch",
                "tickGet",
                "unAuthLogAdd",
                "httpUnAuthHandle",
                "jsonObjectAddInt",
                "httpGenAuthKey",
                "strncpy",
                "jsonObjectObjectAdd",
                "httpGenDictionary",
                "jsonObjectAddString",
                "jsonObjectFromString",
                "snprintf",
                "modelWrite",
                "httpDoAuthorize",
                "jsonObjectGetString",
                "unAuthLogOutput",
                "jsonObjectObjectGet",
                "strcpy",
                "memcmp",
                "unAuthLogAddIpv6",
                "httpGenTmpAuthKey",
                "httpDoChangePwd",
                "sessionMatchIpv6",
                "notifySecdataChanged",
                "httpProcDataSrv"
            ],
            "top_func": "httpProcDataSrv"
        },
        {
            "id": "24",
            "funcs": [
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "httpRecvReply",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "httpRecvReply"
        },
        {
            "id": "25",
            "funcs": [
                "jsonObjectGetString",
                "hostWds2gJsonToBin",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "hostWds2gJsonToBin"
        },
        {
            "id": "26",
            "funcs": [
                "logOutput",
                "jsonObjectGetString",
                "mcbAlign",
                "strcpy",
                "memset",
                "strncpy",
                "modelRead",
                "checkDownloadStatus",
                "uninstallPluginReqHandle",
                "snprintf",
                "downloadProcessKickoff",
                "modelWrite",
                "mcbFree"
            ],
            "top_func": "uninstallPluginReqHandle"
        },
        {
            "id": "27",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "wlan5gWdsSetPhyMode",
                "_eventSendMsgVal32",
                "wlanWdsSetChannel",
                "_eventSendMsgId",
                "apps_wssEventIndicate",
                "spliter",
                "readProFile",
                "wlan5gWdsSetChannel",
                "mcbAlign",
                "flashReadUID",
                "select",
                "modelRead",
                "wlanWdsSetPhyMode",
                "_chkWlanReload",
                "MmtAtePrase",
                "_eventIndicate",
                "memcpy",
                "my_printf",
                "wlanSwASCtoKey",
                "readTpHead",
                "strncpy",
                "ctrlMonitorDoAction",
                "snprintf",
                "macBinToString",
                "miniFsReadFile",
                "strncmp",
                "printf",
                "sendto",
                "sprintf",
                "rsaVerifySignByBase64EncodePublicKeyBlob",
                "wlan5gWdsSetBandWidth",
                "wlanWdsSetBandWidth",
                "writeProFile",
                "apps_wssTaskHandler",
                "_tWlanTask",
                "memcmp",
                "MmtAte",
                "mcbFree"
            ],
            "top_func": "_tWlanTask"
        },
        {
            "id": "28",
            "funcs": [
                "jsonObjectGetString",
                "strlen",
                "memset",
                "hostWds5gJsonToBin",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "hostWds5gJsonToBin"
        },
        {
            "id": "3",
            "funcs": [
                "logOutput",
                "httpDefAuthKey",
                "jsonObjectNewObject",
                "jsonObjectNextSubObject",
                "httpGetPassword",
                "httpCleanSessionClient",
                "strlen",
                "memset",
                "strcmp",
                "httpChangeSession",
                "strchr",
                "modelDecodeSC",
                "httpCleanSessionClientIpv6",
                "doActionToModel",
                "FUN_404c9fe8",
                "modelRead",
                "jsonObjectAddIntByStr",
                "jsonObjectAddInt",
                "strncpy",
                "modelWrite",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectIsObject",
                "strcpy",
                "httpDoChangePwd",
                "notifySecdataChanged"
            ],
            "top_func": "FUN_404c9fe8"
        },
        {
            "id": "4",
            "funcs": [
                "recvfrom",
                "memcpy",
                "memset",
                "close",
                "tftpSendRequest",
                "tftpSendDetectServer",
                "tftpcDownloadFile",
                "socket",
                "bind"
            ],
            "top_func": "tftpcDownloadFile"
        },
        {
            "id": "5",
            "funcs": [
                "recvfrom",
                "copy_msg_element",
                "protocol_handler",
                "logOutput",
                "csum__2",
                "get_node",
                "devDiscoverHandle",
                "memset",
                "strncpy",
                "parse_msg_element",
                "get_new_node",
                "parse_advertisement_frame",
                "send_advertisement_frame",
                "memcmp",
                "memcpy",
                "parse_discovery_frame",
                "ms_idle_handler"
            ],
            "top_func": "devDiscoverHandle"
        },
        {
            "id": "6",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "7",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "8",
            "funcs": [
                "cloudComHelloCloudRspSef",
                "logOutput",
                "strstr",
                "jsonObjectGetString",
                "strlen",
                "cloudComSetReconnectTime",
                "memset",
                "strncpy",
                "cloudComSendHelloCloudToSefError",
                "modelRead",
                "sysClkRateGet",
                "atoi",
                "snprintf",
                "cloudComSetStopConnect",
                "memcpy",
                "jsonObjectGetInt",
                "tickGet",
                "cloudComGetConfigInfo"
            ],
            "top_func": "cloudComHelloCloudRspSef"
        },
        {
            "id": "9",
            "funcs": [
                "logOutput",
                "get2ndDomain",
                "jsonObjectGetString",
                "getDomainListResultHandle",
                "jsonObjectObjectGet",
                "saveUseState",
                "strlen",
                "memset",
                "strncpy",
                "commonResultHandle",
                "jsonObjectArrayGetIdx",
                "modelRead",
                "jsonObjectArrayLength",
                "memcmp",
                "mcbMalloc",
                "memcpy",
                "macStr2Eth",
                "mcbFree"
            ],
            "top_func": "getDomainListResultHandle"
        }
    ],
    "10400_wdr7661_result": [
        {
            "id": "0",
            "funcs": [
                "FUN_404ae904",
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "FUN_404ae904"
        },
        {
            "id": "1",
            "funcs": [
                "recvfrom",
                "logOutput",
                "strstr",
                "printf",
                "strchr",
                "strlen",
                "memset",
                "strncpy",
                "ssdpSendReply",
                "miniUPnPSSDPHandle",
                "snprintf",
                "strncasecmp",
                "strncopy",
                "memcpy",
                "ssdpFlag"
            ],
            "top_func": "miniUPnPSSDPHandle"
        },
        {
            "id": "10",
            "funcs": [
                "logOutput",
                "pluginNoneTableReset",
                "utf8Truncate",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "mcbAlign",
                "strcpy",
                "strlen",
                "addUninstalledPluginToTable",
                "memset",
                "strncpy",
                "jsonObjectArrayGetIdx",
                "encodeLogSC",
                "getNotInsPluginResultHandle",
                "jsonObjectArrayLength",
                "jsonObjectGetInt",
                "mcbFree"
            ],
            "top_func": "getNotInsPluginResultHandle"
        },
        {
            "id": "11",
            "funcs": [
                "__getDstInfo",
                "strtok_r",
                "strcpy",
                "strncpy",
                "bzero",
                "atoi",
                "getenv",
                "strcmp"
            ],
            "top_func": "__getDstInfo"
        },
        {
            "id": "12",
            "funcs": [
                "recvfrom",
                "memcpy",
                "tftpSendDetectServer",
                "tftpSendFile"
            ],
            "top_func": "tftpSendFile"
        },
        {
            "id": "13",
            "funcs": [
                "jsonObjectGetString",
                "strlen",
                "memset",
                "FUN_40330284",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330284"
        },
        {
            "id": "14",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "15",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "FUN_403097b8",
                "select",
                "apps_wssTaskHandler",
                "MmtAtePrase",
                "_chkWlanReload",
                "_eventIndicate",
                "strncmp",
                "memcpy",
                "MmtAte",
                "spliter"
            ],
            "top_func": "FUN_403097b8"
        },
        {
            "id": "16",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "17",
            "funcs": [
                "recvfrom",
                "strlen",
                "memset",
                "wlan5gWdsSetPhyMode",
                "_eventSendMsgVal32",
                "wlanWdsSetChannel",
                "_eventSendMsgId",
                "apps_wssEventIndicate",
                "spliter",
                "readProFile",
                "wlan5gWdsSetChannel",
                "mcbAlign",
                "flashReadUID",
                "select",
                "modelRead",
                "wlanWdsSetPhyMode",
                "_chkWlanReload",
                "MmtAtePrase",
                "_eventIndicate",
                "memcpy",
                "my_printf",
                "wlanSwASCtoKey",
                "readTpHead",
                "FUN_403097b8",
                "ctrlMonitorDoAction",
                "strncpy",
                "snprintf",
                "macBinToString",
                "miniFsReadFile",
                "printf",
                "sendto",
                "sprintf",
                "rsaVerifySignByBase64EncodePublicKeyBlob",
                "wlan5gWdsSetBandWidth",
                "wlanWdsSetBandWidth",
                "apps_wssTaskHandler",
                "writeProFile",
                "memcmp",
                "strncmp",
                "MmtAte",
                "mcbFree"
            ],
            "top_func": "FUN_403097b8"
        },
        {
            "id": "18",
            "funcs": [
                "logOutput",
                "jsonObjectGetString",
                "mcbAlign",
                "strcpy",
                "memset",
                "strncpy",
                "modelRead",
                "checkDownloadStatus",
                "uninstallPluginReqHandle",
                "snprintf",
                "downloadProcessKickoff",
                "modelWrite",
                "mcbFree"
            ],
            "top_func": "uninstallPluginReqHandle"
        },
        {
            "id": "19",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "2",
            "funcs": [
                "jsonObjectGetString",
                "strlen",
                "memset",
                "FUN_40330284",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330284"
        },
        {
            "id": "20",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "21",
            "funcs": [
                "jsonObjectNewObject",
                "memset",
                "sendMsgToCloudBySdk",
                "setOperRequestStatus",
                "modelRead",
                "registerRequestHandle",
                "jsonObjectAddInt",
                "strncpy",
                "chkPwdFormat",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "modelWrite",
                "jsonObjectGetInt",
                "jsonObjectGetString",
                "strcpy",
                "cloudOperIsCanRequest",
                "chkVeriCodeFormat",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "registerRequestHandle"
        },
        {
            "id": "22",
            "funcs": [
                "logOutput",
                "copy_msg_element",
                "protocol_handler",
                "get_node",
                "recvfrom",
                "memset",
                "strncpy",
                "parse_msg_element",
                "get_new_node",
                "parse_advertisement_frame",
                "csum",
                "send_advertisement_frame",
                "FUN_404d16f4",
                "memcmp",
                "memcpy",
                "parse_discovery_frame",
                "ms_idle_handler"
            ],
            "top_func": "FUN_404d16f4"
        },
        {
            "id": "23",
            "funcs": [
                "httpDefAuthKey",
                "logOutput",
                "jsonObjectNewObject",
                "strlen",
                "unAuthLogCleanIpv6",
                "memset",
                "httpResetContext",
                "authLoginSuccessPushInfo",
                "authLoginSuccessPushInfoIpv6",
                "jsonObjectObjectDelete",
                "strcmp",
                "jsonObjectToString",
                "nd6_get_mac_by_ip",
                "jsonObjectObjectIsNull",
                "httpChangeSession",
                "strchr",
                "memmove",
                "staMgtFindRuntimeEntryById",
                "modelDecodeSC",
                "httpProcDsMethod",
                "unAuthLogClean",
                "modelEncodeSC",
                "modelRead",
                "memcpy",
                "sessionMatch",
                "tickGet",
                "unAuthLogAdd",
                "httpUnAuthHandle",
                "jsonObjectAddInt",
                "httpGenAuthKey",
                "strncpy",
                "jsonObjectObjectAdd",
                "httpGenDictionary",
                "jsonObjectAddString",
                "jsonObjectFromString",
                "snprintf",
                "modelWrite",
                "httpDoAuthorize",
                "jsonObjectGetString",
                "unAuthLogOutput",
                "jsonObjectObjectGet",
                "strcpy",
                "memcmp",
                "unAuthLogAddIpv6",
                "httpGenTmpAuthKey",
                "httpDoChangePwd",
                "sessionMatchIpv6",
                "notifySecdataChanged",
                "httpProcDataSrv"
            ],
            "top_func": "httpProcDataSrv"
        },
        {
            "id": "24",
            "funcs": [
                "FUN_404ae904",
                "getDownloadSession",
                "logOutput",
                "httpCheckIsRedirectReply",
                "memmove",
                "memset",
                "strncpy",
                "memcmp",
                "recvn"
            ],
            "top_func": "FUN_404ae904"
        },
        {
            "id": "25",
            "funcs": [
                "cloudComHelloCloudRspSef",
                "logOutput",
                "strstr",
                "jsonObjectGetString",
                "strlen",
                "cloudComSetReconnectTime",
                "memset",
                "strncpy",
                "cloudComSendHelloCloudToSefError",
                "modelRead",
                "sysClkRateGet",
                "atoi",
                "snprintf",
                "cloudComSetStopConnect",
                "memcpy",
                "jsonObjectGetInt",
                "tickGet",
                "cloudComGetConfigInfo"
            ],
            "top_func": "cloudComHelloCloudRspSef"
        },
        {
            "id": "26",
            "funcs": [
                "jsonObjectGetString",
                "FUN_40330418",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330418"
        },
        {
            "id": "27",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "3",
            "funcs": [
                "strcpy",
                "__getZoneInfo",
                "getenv",
                "strcmp",
                "strpbrk"
            ],
            "top_func": "__getZoneInfo"
        },
        {
            "id": "4",
            "funcs": [
                "logOutput",
                "recvfrom",
                "isGlobalIpv6Addr",
                "dhcpv6cCtrlCallBk",
                "rtadvcCalIpv6Addr",
                "detectResultHandle",
                "rtadvcUpdateAddr",
                "memset",
                "bcmp",
                "rtadvcFlushAddr",
                "mcbAlign",
                "FUN_4032b5ec",
                "memcpy",
                "strncpy",
                "snprintf",
                "rtadvcFlushGateway",
                "rtadvcUpdateGateway",
                "radvcFlushDns",
                "ip6_sprintf",
                "mcbFree"
            ],
            "top_func": "FUN_4032b5ec"
        },
        {
            "id": "5",
            "funcs": [
                "logOutput",
                "get2ndDomain",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "saveUseState",
                "strlen",
                "memset",
                "strncpy",
                "commonResultHandle",
                "jsonObjectArrayGetIdx",
                "FUN_40324388",
                "modelRead",
                "jsonObjectArrayLength",
                "memcmp",
                "mcbMalloc",
                "memcpy",
                "macStr2Eth",
                "mcbFree"
            ],
            "top_func": "FUN_40324388"
        },
        {
            "id": "6",
            "funcs": [
                "recvfrom",
                "memcpy",
                "memset",
                "close",
                "tftpSendRequest",
                "tftpSendDetectServer",
                "tftpcDownloadFile",
                "socket",
                "bind"
            ],
            "top_func": "tftpcDownloadFile"
        },
        {
            "id": "7",
            "funcs": [
                "jsonObjectNewObject",
                "jsonObjectGetString",
                "bindRequestHandle",
                "unbindRequestHandle",
                "strcpy",
                "strlen",
                "cloudOperIsCanRequest",
                "chkPwdFormat",
                "modelRead",
                "sendMsgToCloudBySdk",
                "jsonObjectObjectAdd",
                "jsonObjectAddString",
                "setOperRequestStatus",
                "getAccountType",
                "jsonObjectObjectDelete"
            ],
            "top_func": "bindRequestHandle"
        },
        {
            "id": "8",
            "funcs": [
                "logOutput",
                "strlen",
                "memset",
                "mcbAlign",
                "modelRead",
                "jsonObjectArrayLength",
                "memcpy",
                "utf8Truncate",
                "strncpy",
                "encodeLogSC",
                "setNewFirmwareDomain",
                "modelWrite",
                "jsonObjectGetInt",
                "getFwListResultHandle",
                "cloudOperNormalResHandle",
                "jsonObjectGetString",
                "jsonObjectObjectGet",
                "jsonObjectArrayGetIdx",
                "memcmp",
                "mcbFree"
            ],
            "top_func": "getFwListResultHandle"
        },
        {
            "id": "9",
            "funcs": [
                "jsonObjectGetString",
                "FUN_40330418",
                "strlen",
                "memset",
                "memcpy",
                "jsonObjectGetInt",
                "macStr2Eth"
            ],
            "top_func": "FUN_40330418"
        }
    ]
}"""

class FlowNode:

    def __init__(self, vn):
        self.vn = vn

    def get_value(self):
        if self.vn.isAddress():
            vn_data = getDataAt(self.vn.getAddress())
            if not vn_data:
                return None
            return vn_data.getValue()
        elif self.vn.isConstant():
            return self.vn.getAddress()
        elif self.vn.isUnique():
            return self.calc_pcode(self.vn.getDef())
        elif self.vn.isRegister():
            return self.calc_pcode(self.vn.getDef())
        elif self.vn.isAddrTied():
            return self.calc_pcode(self.vn.getDef())

    def calc_pcode(self, pcode):
        if isinstance(pcode, PcodeOpAST):
            opcode = pcode.getOpcode()
            if opcode == PcodeOp.PTRSUB:
                var_node_1 = FlowNode(pcode.getInput(0))
                var_node_2 = FlowNode(pcode.getInput(1))
                value_1 = var_node_1.get_value()
                value_2 = var_node_2.get_value()
                if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                    return toAddr(value_1.offset + value_2.offset)
                else:
                    return None
            elif opcode == PcodeOp.PTRADD:
                var_node_0 = FlowNode(pcode.getInput(0))
                var_node_1 = FlowNode(pcode.getInput(1))
                var_node_2 = FlowNode(pcode.getInput(2))
                try:
                    value_0 = var_node_0.get_value()
                    if not isinstance(value_0, GenericAddress):
                        return
                    value_1 = var_node_1.get_value()
                    if not isinstance(value_1, GenericAddress):
                        return
                    if pcode.getNumInputs() == 3:
                        value_2 = var_node_2.get_value()
                        if not isinstance(value_2, GenericAddress):
                            return
                        return toAddr(value_0.offset + value_1.offset * value_2.offset)
                    elif pcode.getNumInputs() == 2:
                        return toAddr(value_0.offset + value_1.offset)
                except Exception as err:
                    return None
                except:
                    return None
            elif opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT or opcode == PcodeOp.CAST:
                var_node_1 = FlowNode(pcode.getInput(0))
                value_1 = var_node_1.get_value()
                if isinstance(value_1, GenericAddress):
                    return value_1
                else:
                    return None
        else:
            return None


TERMINATOR = '\00'

func_map = {
    # 'nvram_get': 1,
    # 'nvram_set': 1,
    # 'modelWrite': 1,
    # 'modelRead': 1,
    'getenv': 1,
    'setenv': 1
}

def init_func_map():
    func_map = {}
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    for item in funcs:
        func_name = item.getName()
        if func_name not in func_map:
            func_map[func_name] = []
        func_map[func_name].append(item)
    return func_map

def custom_get_function(func_name):
    global GLOBAL_FUNC_MAP
    if func_name in GLOBAL_FUNC_MAP:
        return GLOBAL_FUNC_MAP[func_name][0]
    return None

def custom_get_str(addr, length):
    ret = ""
    for i in range(length):
        b = currentProgram.getMemory().getByte(addr)
        if b >= 0x20 and b <= 0x7f:
            ret += chr(b)
        addr = addr.addNoWrap(1)
    return ret

def get_str_from_vn(vn):
    val = FlowNode(vn).get_value()
    if val and (
    isinstance(val, GenericAddress)) and currentProgram.getMaxAddress() >= val >= currentProgram.getMinAddress():
        data = getDataAt(val)
        if data and data.hasStringValue():
            return data.getValue().strip('"')
        if not data:
            end_addr = find(val, TERMINATOR)
            if not end_addr:
                return None
            length = end_addr.getOffset() - val.getOffset()
            if length > 1:
                str_data = custom_get_str(val, length)
                return str_data.strip('"')
    return None

def get_key_from_vn(vn):
    if not vn:
        return None
    ret = get_str_from_vn(vn)
    if ret:
        return ret
    if vn.isAddress():
        vn_data = getDataAt(vn.getAddress())
        if not vn_data:
            return
        val = vn_data.getValue()
    else:
        val = FlowNode(vn).get_value()
    if val:
        if isinstance(val, Scalar):
            return val.getValue()
        return val.getOffset()
    return None

hfunc_cache = {}


def get_hfunction(func):
    func_entry_offset = func.getEntryPoint().getOffset()
    if func_entry_offset in hfunc_cache:
        return hfunc_cache.get(func_entry_offset)
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 10
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    hfunc_cache[func_entry_offset] = hfunction
    return hfunction

def get_key(hfunc,fromAddr,func_name):
    for item in hfunc.getPcodeOps(fromAddr):
        if item.getOpcode() == PcodeOp.CALL and item.getNumInputs() > 1:
            this_func = getFunctionAt(item.getInput(0).getAddress())
            if this_func and this_func.getName() == func_name:
                key_vn = item.getInput(func_map[func_name])
                return get_key_from_vn(key_vn)

def get_calling_funcs(target_func,count):
    ret = set()
    source_refs = currentProgram.getReferenceManager().getReferencesTo(target_func.getEntryPoint())
    for cref in source_refs:
        fromAddr = cref.getFromAddress()
        callingFunc = getFunctionContaining(fromAddr)
        if not callingFunc:
            continue
        ret.add(callingFunc)
    new_ret = list(ret)
    return new_ret[:count]

def get_top_funcs(from_addr):
    ret = []
    caller = getFunctionContaining(from_addr)
    if not caller:
        return ret
    queue = Queue.Queue()
    queue.put([caller])
    while not queue.empty():
        current = queue.get()
        limit_num = 4-len(current)
        if limit_num <= 0:
            limit_num = 1
        calling_funcs = get_calling_funcs(current[-1],limit_num)
        if len(calling_funcs) == 0:
            ret.append(current)
            continue
        for item in calling_funcs:
            if item.getEntryPoint().getOffset() in [x.getEntryPoint().getOffset() for x in current]:
                ret.append(current)
                continue
            else:
                queue.put(current[:] + [item])
    new_ret = set()
    for item in ret:
        new_ret.add(item[-1].getName())
    return list(new_ret)

def handle_funcs():
    res = []
    for key in func_map:
        target = custom_get_function(key)
        if not target:
            continue
        source_refs = currentProgram.getReferenceManager().getReferencesTo(target.getEntryPoint())
        for ref in source_refs:
            fromAddr = ref.getFromAddress()
            callingFunc = getFunctionContaining(fromAddr)
            if not callingFunc:
                continue
            hfunc = get_hfunction(callingFunc)
            if not hfunc:
                continue
            this_key = get_key(hfunc,fromAddr,key)
            if not this_key:
                continue
            top_funcs = get_top_funcs(fromAddr)
            if top_funcs:
                res.append({
                    'name':key,
                    'key':this_key,
                    'top_funcs': top_funcs
                })
    return res

def get_global_offset(vn):

    if vn.isAddress():
        has_func = getFunctionContaining(vn.getAddress())
        if has_func:
            return None
        data = getDataAt(vn.getAddress())
        if data and data.isPointer():
            return None
        if not data or not data.hasStringValue():
            return vn.getAddress().getOffset()
    return None


def handle_global():
    res = []
    print(currentProgram.getFunctionManager().getFunctionCount())
    count = 0
    for func in currentProgram.getFunctionManager().getFunctions(True):
        count += 1
        print(count,func.getName())
        high_func = get_hfunction(func)
        if not high_func:
            continue
        for item in high_func.getPcodeOps():
            for vn in item.getInputs():
                global_offset = get_global_offset(vn)
                if global_offset:
                    fromAddr = item.getSeqnum().getTarget()
                    top_funcs = get_top_funcs(fromAddr)
                    if top_funcs:
                        res.append({
                            'fromAddr': str(fromAddr),
                            'key':hex(global_offset),
                            'top_funcs': top_funcs
                        })
    return res

def handle_global2(funcs):
    res = []
    count = 0
    for func in currentProgram.getFunctionManager().getFunctions(True):
        count += 1
        if func.getName() not in funcs:
            continue
        high_func = get_hfunction(func)
        if not high_func:
            continue
        for item in high_func.getPcodeOps():
            for vn in item.getInputs():
                global_offset = get_global_offset(vn)
                if global_offset:
                    res.append(hex(global_offset))
    return res

def change_func_sign(sign, func):
    try:
        parser = FunctionSignatureParser(currentProgram.getDataTypeManager(), DefaultDataTypeManagerService())
        # print("sign: %r"%sign)
        fddt = parser.parse(func.getSignature(), sign)
        cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), fddt, SourceType.USER_DEFINED, True, True)
        cmd.applyTo(currentProgram, getMonitor())
    except Exception as e:
        print("chang func sign failed for {} -> {}".format(func.getName(), sign))

# apply simresult to current program
if os.access(currentProgram.getExecutablePath() + '.simresult', os.F_OK):
    print("Reading simresult from %s" % (currentProgram.getExecutablePath() + '.simresult'))
    with open(currentProgram.getExecutablePath() + '.simresult', 'r') as f:
        simresults = json.load(f)
else:
    print("No simresult found")
    simresults = None
if simresults:
    for simresult in simresults:
        offset = int(simresult['offset'], 16)
        funcName = simresult['funcName']
        function = getFunctionAt(toAddr(offset))
        if function:
            try:
                function.setName(funcName, SourceType.DEFAULT)
            except DuplicateNameException as e:
                print("DuplicateNameException:",e)
        elif not createFunction(toAddr(offset), funcName):
            print("Failed to create function %s @ 0x%08x" % (funcName, offset))
        funcSign = simresult.get('funcSign')
        function = getFunctionAt(toAddr(offset))
        if funcSign and function:
            change_func_sign(funcSign, function)

GLOBAL_FUNC_MAP = init_func_map()

def main():
    all_tree_funcs = json.loads(TREE_FUNCS)
    output_dir_name = currentProgram.getExecutablePath().split('/')[-1] + '_result'
    this_tree_funcs = all_tree_funcs[output_dir_name]
    if os.path.exists('%s/findtrace_output/%s' % (os.getcwd(), output_dir_name)):
        return
    os.system('mkdir -p %s/findtrace_output/%s' % (os.getcwd(), output_dir_name))
    global_res = []
    for tree in this_tree_funcs:
        globals = handle_global2(tree['funcs'])
        global_res.append({
            'id':tree['id'],
            'globals':globals,
            'top_func':tree['top_func']
        })
    with open('findtrace_output/%s/res.json' % (output_dir_name, ), 'w') as f:
        f.write(json.dumps({
            'global': global_res
        }))


if __name__ == '__main__':
    main()