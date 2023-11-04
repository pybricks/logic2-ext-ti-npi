# High Level Analyzer
# For more information and documentation, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from enum import IntEnum
from struct import unpack_from
from typing import Any, Dict, Generator, List

from saleae.analyzers import AnalyzerFrame, ChoicesSetting, HighLevelAnalyzer

SOF = 0xFE


class PacketType(IntEnum):
    CMD = 0x01
    ACL_DATA = 0x02
    SCO_DATA = 0x03
    EVENT = 0x04


class Opcode(IntEnum):
    @classmethod
    def _missing_(cls, value):
        pseudo_member = cls._member_type_.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"Unknown opcode: 0x{value:04X}"
        return pseudo_member

    HCI_DISCONNECT = 0x0406
    HCI_READ_REMOTE_VERSION_INFO = 0x041D
    HCI_SET_EVENT_MASK = 0x0C01
    HCI_RESET = 0x0C03
    HCI_READ_TRANSMIT_POWER = 0x0C2D
    HCI_SET_CONTROLLER_TO_HOST_FLOW_CONTROL = 0x0C31
    HCI_HOST_BUFFER_SIZE = 0x0C33
    HCI_HOST_NUM_COMPLETED_PACKETS = 0x0C35
    HCI_SET_EVENT_MASK_PAGE_2 = 0x0C63
    HCI_READ_AUTH_PAYLOAD_TIMEOUT = 0x0C7B
    HCI_WRITE_AUTH_PAYLOAD_TIMEOUT = 0x0C7C
    HCI_READ_LOCAL_VERSION_INFO = 0x1001
    HCI_READ_LOCAL_SUPPORTED_COMMANDS = 0x1002
    HCI_READ_LOCAL_SUPPORTED_FEATURES = 0x1003
    HCI_READ_BDADDR = 0x1009
    HCI_READ_RSSI = 0x1405
    HCI_LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x2007

    HCI_EXT_SET_RX_GAIN = 0xFC00
    HCI_EXT_SET_TX_POWER = 0xFC01
    HCI_EXT_ONE_PKT_PER_EVT = 0xFC02
    HCI_EXT_CLK_DIVIDE_ON_HALT = 0xFC03
    HCI_EXT_DECLARE_NV_USAGE = 0xFC04
    HCI_EXT_DECRYPT = 0xFC05
    HCI_EXT_SET_LOCAL_SUPPORTED_FEATURES = 0xFC06
    HCI_EXT_SET_FAST_TX_RESP_TIME = 0xFC07
    HCI_EXT_MODEM_TEST_TX = 0xFC08
    HCI_EXT_MODEM_HOP_TEST_TX = 0xFC09
    HCI_EXT_MODEM_TEST_RX = 0xFC0A
    HCI_EXT_END_MODEM_TEST = 0xFC0B
    HCI_EXT_SET_BDADDR = 0xFC0C
    HCI_EXT_SET_SCA = 0xFC0D
    HCI_EXT_ENABLE_PTM = 0xFC0E
    HCI_EXT_SET_FREQ_TUNE = 0xFC0F
    HCI_EXT_SAVE_FREQ_TUNE = 0xFC10
    HCI_EXT_SET_MAX_DTM_TX_POWER = 0xFC11
    HCI_EXT_MAP_PM_IO_PORT = 0xFC12
    HCI_EXT_DISCONNECT_IMMED = 0xFC13
    HCI_EXT_PER = 0xFC14
    HCI_EXT_PER_BY_CHAN = 0xFC15
    HCI_EXT_EXTEND_RF_RANGE = 0xFC16
    HCI_EXT_ADV_EVENT_NOTICE = 0xFC17
    HCI_EXT_CONN_EVENT_NOTICE = 0xFC18
    HCI_EXT_HALT_DURING_RF = 0xFC19
    HCI_EXT_OVERRIDE_SL = 0xFC1A
    HCI_EXT_BUILD_REVISION = 0xFC1B
    HCI_EXT_DELAY_SLEEP = 0xFC1C
    HCI_EXT_RESET_SYSTEM = 0xFC1D
    HCI_EXT_OVERLAPPED_PROCESSING = 0xFC1E
    HCI_EXT_NUM_COMPLETED_PKTS_LIMIT = 0xFC1F
    HCI_EXT_GET_CONNECTION_INFO = 0xFC20

    HCI_EXT_RESETSYSTEMCMD = 0xFC1D

    ATT_CMD_ERROR_RSP = 0xFD01
    ATT_CMD_EXCHANGEMTUREQ = 0xFD02
    ATT_CMD_EXCHANGE_MTU_RSP = 0xFD03
    ATT_CMD_FINDINFOREQ = 0xFD04
    ATT_CMD_FINDINFORSP = 0xFD05
    ATT_CMD_FIND_BY_TYPE_VALUE_REQ = 0xFD06
    ATT_CMD_FIND_BY_TYPE_VALUE_RSP = 0xFD07
    ATT_CMD_READ_BY_TYPE_VALUE_REQ = 0xFD08
    ATT_CMD_READ_BY_TYPE_VALUE_RSP = 0xFD09
    ATT_CMD_READREQ = 0xFD0A
    ATT_CMD_READ_RSP = 0xFD0B
    ATT_CMD_READBLOBREQ = 0xFD0C
    ATT_CMD_READBLOBRSP = 0xFD0D
    ATT_CMD_READMULTIREQ = 0xFD0E
    ATT_CMD_READMULTIRSP = 0xFD0F
    ATT_CMD_READBYGRPTYPEREQ = 0xFD10
    ATT_CMD_READ_BY_GRP_TYPE_RSP = 0xFD11
    ATT_CMD_WRITEREQ = 0xFD12
    ATT_CMD_WRITE_RSP = 0xFD13
    ATT_CMD_PREPAREWRITEREQ = 0xFD16
    ATT_CMD_PREPAREWRITERSP = 0xFD17
    ATT_CMD_EXECUTEWRITEREQ = 0xFD18
    ATT_CMD_EXECUTEWRITERSP = 0xFD19
    ATT_CMD_HANDLE_VALUE_NOTI = 0xFD1B
    ATT_CMD_HANDLEVALUEIND = 0xFD1D
    ATT_CMD_HANDLEVALUECFM = 0xFD1E

    GATT_EXCHANGEMTU = 0xFD82
    GATT_DISCALLPRIMARYSERVICES = 0xFD90
    GATT_DISCPRIMARYSERVICEBYUUID = 0xFD86
    GATT_FINDINCLUDEDSERVICES = 0xFDB0
    GATT_DISCALLCHARS = 0xFDB2
    GATT_DISC_CHARS_BY_UUID = 0xFD88
    GATT_DISCALLCHARDESCS = 0xFD84
    GATT_READCHARVALUE = 0xFD8A
    GATT_READUSINGCHARUUID = 0xFDB4
    GATT_READLONGCHARVALUE = 0xFD8C
    GATT_READMULTILCHARVALUES = 0xFD8E
    GATT_WRITE_NO_RSP = 0xFDB6
    GATT_SIGNEDWRITENORSP = 0xFDB8
    GATT_WRITE_CHAR_VALUE = 0xFD92
    GATT_WRITELONGCHARVALUE = 0xFD96
    GATT_READCHARDESC = 0xFDBC
    GATT_READLONGCHARDESC = 0xFDBE
    GATT_ADDSERVICE = 0xFDFC
    GATT_WRITECHARDESC = 0xFDC0
    GATT_WRITELONGCHARDESC = 0xFDC2
    GATT_NOTIFICATION = 0xFD9B
    GATT_INDICATION = 0xFD9D
    GATT_DELSERVICE = 0xFDFD
    GATT_ADDATTRIBUTE = 0xFDFE
    GATT_UPDATEMTU = 0xFDFF

    GAP_DEVICE_INIT = 0xFE00
    GAP_AUTHENTICATE = 0xFE0B
    GAP_TERMINATEAUTH = 0xFE10
    GAP_UPDATELINKPARAMREQ = 0xFE11
    GAP_CONFIG_DEVICE_ADDR = 0xFE03
    GAP_DEVICE_DISCOVERY_REQUEST = 0xFE04
    GAP_DEVICE_DISCOVERY_CANCEL = 0xFE05
    GAP_MAKE_DISCOVERABLE = 0xFE06
    GAP_UPDATE_ADVERTISING_DATA = 0xFE07
    GAP_END_DISCOVERABLE = 0xFE08
    GAP_ESTABLISH_LINK_REQUEST = 0xFE09
    GAP_TERMINATE_LINK_REQUEST = 0xFE0A
    GAP_UPDATELINKPARAMREQREPLY = 0xFFFE
    GAP_REGISTERCONNEVENT = 0xFE13
    GAP_BOND = 0xFE0F
    GAP_SIGNABLE = 0xFE0E
    GAP_PASSKEYUPDATE = 0xFE0C
    GAP_SENDSLAVESECURITYREQUEST = 0xFE0D
    GAPCONFIG_SETPARAMETER = 0xFE2F
    GAP_SETPARAMVALUE = 0xFE30
    GAP_GETPARAMVALUE = 0xFE31
    GAP_RESOLVE_PRIVATE_ADDRESS = 0xFE32
    GAP_SET_ADV_TOKEN = 0xFE33
    GAP_REMOVE_ADV_TOKEN = 0xFE34
    GAP_UPDATE_ADV_TOKENS = 0xFE35
    GAP_BOND_MGR_SET_PARAMETER = 0xFE36

    GAPSCAN_ENABLE = 0xFE51
    GAPSCAN_DISABLE = 0xFE52
    GAPSCAN_SETPHYPARAMS = 0xFE53
    GAPSCAN_GETPHYPARAMS = 0xFE54
    GAPSCAN_SETPARAM = 0xFE55
    GAPSCAN_GETPARAM = 0xFE56
    GAPSCAN_SETEVENTMASK = 0xFE57
    GAPSCAN_GETADVREPORT = 0xFE58
    GAPINIT_SETPHYPARAM = 0xFE60
    GAPINIT_GETPHYPARAM = 0xFE61
    GAPINIT_CONNECT = 0xFE62
    GAPINIT_CONNECTWL = 0xFE63
    GAPINIT_CANCELCONNECT = 0xFE64

    HCI_UTIL_UNKNOWN1 = 0xFE87
    HCI_UTIL_GET_LEGO_FW_VERSION = 0xFE88


class EventType(IntEnum):
    @classmethod
    def _missing_(cls, value):
        pseudo_member = cls._member_type_.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"Unknown event: 0x{value:02X}"
        return pseudo_member

    HCI_EVENT_COMMAND_COMPLETE = 0x0E
    HCI_EVENT_VENDOR_SPECIFIC = 0xFF


class EventOpcode(IntEnum):
    @classmethod
    def _missing_(cls, value):
        pseudo_member = cls._member_type_.__new__(cls, value)
        pseudo_member._value_ = value
        pseudo_member._name_ = f"Unknown event opcode: 0x{value:04X}"
        return pseudo_member

    HCI_EXT_SET_RX_GAIN_EVENT = 0x0400
    HCI_EXT_SET_TX_POWER_EVENT = 0x0401
    HCI_EXT_ONE_PKT_PER_EVT_EVENT = 0x0402
    HCI_EXT_CLK_DIVIDE_ON_HALT_EVENT = 0x0403
    HCI_EXT_DECLARE_NV_USAGE_EVENT = 0x0404
    HCI_EXT_DECRYPT_EVENT = 0x0405
    HCI_EXT_SET_LOCAL_SUPPORTED_FEATURES_EVENT = 0x0406
    HCI_EXT_SET_FAST_TX_RESP_TIME_EVENT = 0x0407
    HCI_EXT_MODEM_TEST_TX_EVENT = 0x0408
    HCI_EXT_MODEM_HOP_TEST_TX_EVENT = 0x0409
    HCI_EXT_MODEM_TEST_RX_EVENT = 0x040A
    HCI_EXT_END_MODEM_TEST_EVENT = 0x040B
    HCI_EXT_SET_BDADDR_EVENT = 0x040C
    HCI_EXT_SET_SCA_EVENT = 0x040D
    HCI_EXT_ENABLE_PTM_EVENT = 0x040E
    HCI_EXT_SET_FREQ_TUNE_EVENT = 0x040F
    HCI_EXT_SAVE_FREQ_TUNE_EVENT = 0x0410
    HCI_EXT_SET_MAX_DTM_TX_POWER_EVENT = 0x0411
    HCI_EXT_MAP_PM_IO_PORT_EVENT = 0x0412
    HCI_EXT_DISCONNECT_IMMED_EVENT = 0x0413
    HCI_EXT_PER_EVENT = 0x0414
    HCI_EXT_PER_BY_CHAN_EVENT = 0x0415
    HCI_EXT_EXTEND_RF_RANGE_EVENT = 0x0416
    HCI_EXT_ADV_EVENT_NOTICE_EVENT = 0x0417
    HCI_EXT_CONN_EVENT_NOTICE_EVENT = 0x0418
    HCI_EXT_HALT_DURING_RF_EVENT = 0x0419
    HCI_EXT_OVERRIDE_SL_EVENT = 0x041A
    HCI_EXT_BUILD_REVISION_EVENT = 0x041B
    HCI_EXT_DELAY_SLEEP_EVENT = 0x041C
    HCI_EXT_RESET_SYSTEM_EVENT = 0x041D
    HCI_EXT_OVERLAPPED_PROCESSING_EVENT = 0x041E
    HCI_EXT_NUM_COMPLETED_PKTS_LIMIT_EVENT = 0x041F
    HCI_EXT_GET_CONNECTION_INFO_EVENT = 0x0420

    L2CAP_COMMAND_REJECT = 0x0481
    L2CAP_CONNECTION_PARAMETER_UPDATE_RESPONSE = 0x0493
    L2CAP_CONNECTION_REQUEST = 0x0494
    L2CAP_CHANNEL_ESTABLISHED = 0x04E0
    L2CAP_CHANNEL_TERMINATED = 0x04E1
    L2CAP_OUT_OF_CREDIT = 0x04E2
    L2CAP_PEER_CREDIT_THRESHOLD = 0x04E3
    L2CAP_SEND_SDU_DONE = 0x04E4
    L2CAP_DATA = 0x04F0

    ATT_EVENT_ERROR_RSP = 0x0501
    ATT_EVENT_EXCHANGE_MTU_REQ = 0x0502
    ATT_EVENT_EXCHANGEMTURSP = 0x0503
    ATT_EVENT_FINDINFOREQ = 0x0504
    ATT_EVENT_FINDINFORSP = 0x0505
    ATT_EVENT_FIND_BY_TYPE_VALUE_REQ = 0x0506
    ATT_EVENT_FIND_BY_TYPE_VALUE_RSP = 0x0507
    ATT_EVENT_READ_BY_TYPE_REQ = 0x0508
    ATT_EVENT_READ_BY_TYPE_RSP = 0x0509
    ATT_EVENT_READ_REQ = 0x050A
    ATT_EVENT_READRSP = 0x050B
    ATT_EVENT_READBLOBREQ = 0x050C
    ATT_EVENT_READBLOBRSP = 0x050D
    ATT_EVENT_READMULTIREQ = 0x050E
    ATT_EVENT_READMULTIRSP = 0x050F
    ATT_EVENT_READ_BY_GRP_TYPE_REQ = 0x0510
    ATT_EVENT_READ_BY_GRP_TYPE_RSP = 0x0511
    ATT_EVENT_WRITE_REQ = 0x0512
    ATT_EVENT_WRITE_RSP = 0x0513
    ATT_EVENT_PREPAREWRITEREQ = 0x0516
    ATT_EVENT_PREPAREWRITERSP = 0x0517
    ATT_EVENT_EXECUTEWRITEREQ = 0x0518
    ATT_EVENT_EXECUTEWRITERSP = 0x0519
    ATT_EVENT_HANDLE_VALUE_NOTI = 0x051B
    ATT_EVENT_HANDLEVALUEIND = 0x051D
    ATT_EVENT_HANDLEVALUECFM = 0x051E
    ATT_EVENT_FLOWCTRLVIOLATED = 0x057E
    ATT_EVENT_MTUUPDATEDEVT = 0x051F

    GAP_DEVICE_INIT_DONE = 0x0600
    GAP_DEVICE_DISCOVERY_DONE = 0x0601
    GAP_ADVERT_DATA_UPDATE_DONE = 0x0602
    GAP_MAKE_DISCOVERABLE_DONE = 0x0603
    GAP_END_DISCOVERABLE_DONE = 0x0604
    GAP_LINK_ESTABLISHED = 0x0605
    GAP_LINK_TERMINATED = 0x0606
    GAP_LINK_PARAM_UPDATE = 0x0607
    GAP_SIGNATUREUPDATED = 0x0609
    GAP_PASSKEYNEEDED = 0x0609
    GAP_AUTHENTICATIONCOMPLETE = 0x0609
    GAP_SLAVEREQUESTEDSECURITY = 0x0609
    GAP_BONDCOMPLETE = 0x0609
    GAP_PAIRINGREQUESTED = 0x0609
    GAP_CONNECTINGCANCELLED = 0x0609
    GAP_CONNECTIONEVENTNOTICE = 0x0609
    GAP_LINKPARAMUPDATEREQEST = 0x0609
    GAP_DEVICE_INFORMATION = 0x060D
    GAP_ADVERTISERSCANNEREVENT = 0x0613

    HCI_COMMAND_STATUS = 0x067F


def single_byte_frame(frame: AnalyzerFrame, name: str, value: int) -> AnalyzerFrame:
    return AnalyzerFrame(
        "byte", frame.start_time, frame.end_time, dict(name=name, value=value)
    )


def decode_payload(data: bytearray) -> Dict[str, Any]:
    result = {}

    packet_type = PacketType(data[0])
    result["type"] = packet_type.name

    if packet_type == PacketType.CMD:
        opcode = Opcode(unpack_from("<H", data, 1)[0])
        result["cmd"] = opcode.name

    elif packet_type == PacketType.EVENT:
        event = EventType(data[1])
        result["event"] = event.name

        if event == EventType.HCI_EVENT_VENDOR_SPECIFIC:
            opcode = EventOpcode(unpack_from("<H", data, 3)[0])
            result["vendor"] = opcode.name

            if opcode == EventOpcode.HCI_COMMAND_STATUS:
                result["status"] = data[5]
                result["cmd"] = Opcode(unpack_from("<H", data, 6)[0]).name

                payload_len = data[8]

                if payload_len:
                    result["payload"] = data[9 : 9 + payload_len]

    return result


def parse_msg(rx: bool) -> Generator[None, AnalyzerFrame, List[AnalyzerFrame]]:
    key = "miso" if rx else "mosi"

    def value(frame: AnalyzerFrame) -> int:
        return frame.data[key][0]

    # skip first byte of RX data since it is delayed by one transfer
    if rx:
        yield

    sof_in = yield
    sof = value(sof_in)

    if sof != SOF:
        return []

    sof_out = single_byte_frame(sof_in, "SOF", sof)

    payload_len_in = yield
    payload_len = value(payload_len_in)
    payload_len_out = single_byte_frame(payload_len_in, "Len", payload_len)

    payload = []
    payload_data = bytearray()
    checksum = payload_len

    for _ in range(payload_len):
        data_in = yield
        data = value(data_in)
        checksum ^= data
        payload.append(data_in)
        payload_data.append(data)

    payload_out = AnalyzerFrame(
        "payload",
        payload[0].start_time,
        payload[-1].end_time,
        dict(**decode_payload(payload_data), fcs=checksum),
    )

    fcs_in = yield
    fcs = value(fcs_in)
    fcs_out = single_byte_frame(fcs_in, "FCS", fcs)

    return [sof_out, payload_len_out, payload_out, fcs_out]


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    tx_or_rx = ChoicesSetting(choices=("tx", "rx"))

    # An optional list of types this analyzer produces, providing a way to
    # customize the way frames are displayed in Logic 2.
    result_types = {"byte": {"format": "{{data.name}}({{data.value}})"}}

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """

        print(
            "Settings:",
            self.tx_or_rx,
        )

        self.parser = None

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer, and optionally return a
        single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        """

        frames = []

        if frame.type == "enable":
            self.parser = parse_msg(self.tx_or_rx == "rx")
            next(self.parser)
        elif frame.type == "disable":
            pass
        elif frame.type == "result":
            if self.parser:
                try:
                    self.parser.send(frame)
                except StopIteration as ex:
                    self.parser = None
                    frames = ex.value
        else:
            print("unexpected frame type:", frame.type)

        return frames
