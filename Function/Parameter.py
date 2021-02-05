import enum
class Layer_ID(enum.Enum):
    BT_GAP  			= b'\x00'
    BLE_GATT  			= b'\x01'
    BLE_GAP  			= b'\x02'
    BLE_SMP  			= b'\x03'
    BLE_TRS 			= b'\x04'
    BT_HFP  			= b'\x05'
    RTU  				= b'\x06'
    DFU  				= b'\x07'
    AVDTP  			    = b'\x08'
    AVCTP  			    = b'\x09'
    AVRCP  			    = b'\x0A'
    BT_L2CAP  			= b'\x0B'
    A2DP  			    = b'\x0C'
    OTA                 = b'\x0D'
    BLE_L2CAP           = b'\x0E'
    PTS_TEST            = b'\x0F'
    PERIPHERAL_LED  	= b'\x10'
    PERIPHERAL_ADC  	= b'\x11'
    PERIPHERAL_SPI  	= b'\x12'
    PERIPHERAL_PWM  	= b'\x13'
    PERIPHERAL_SQIFLASH = b'\x14'
    PERIPHERAL_GPIO 	= b'\x15'
    PERIPHERAL_I2C  	= b'\x16'
    PERIPHERAL_CHG      = b'\x17'
    PERIPHERAL_IAP2     = b'\x18'
    PERIPHERAL_USB_BC   = b'\x19'
    SDP  			    = b'\x20'
    RFCOMM  			= b'\x21'
    SPP 				= b'\x22'
    PBAP  			    = b'\x23'
    GFPS                = b'\x24'
    UTILITY  			= b'\x30'
    EVENT_COMMAND_COMPLETE = b'\x80'

# region BT GAP
class BT_GAP_CMD_ID(enum.Enum):
    TESET  							= b'\x00'
    INQUIRY  						= b'\x01'
    INQUIRY_CANCEL  				= b'\x02'
    CREATE_CONNECTION 				= b'\x03'
    DISCONNECT  					= b'\x04'
    CREATE_CONNECTION_CANCEL 		= b'\x05'
    ACCEPT_CONNECTION_REQUEST 		= b'\x06'
    REJECT_CONNECTION_REQUEST 		= b'\x07'
    PIN_CODE_REQUEST_REPLY   		= b'\x08'
    PIN_CODE_REQUEST_NEGATIVE_REPLY = b'\x09'
    CHANGE_CONNECTION_PACKET_TYPE 	= b'\x0A'
    WRITE_PAGE_TIMEOUT 				= b'\x0B'
    REMOTE_NAME_REQUEST 			= b'\x0C'
    REMOTE_NAME_REQUEST_CANCEL 		= b'\x0D'
    SNIFF_MODE 						= b'\x0E'
    EXIT_SNIFF_MODE 				= b'\x0F'
    SWITCH_ROLE 					= b'\x10'
    WRITE_LINK_POLICY_SETTINGS 		= b'\x11'
    RESET 							= b'\x12'
    WRITE_LOCAL_NAME 				= b'\x13'
    READ_LOCAL_NAME 				= b'\x14'
    READ_PAGE_TIMEOUT 				= b'\x15'
    READ_SCAN_ENABLE 				= b'\x16'
    WRITE_SCAN_ENABLE 				= b'\x17'
    READ_LINK_SUPERVISION_TIMEOUT 	= b'\x18'
    WRITE_LINK_SUPERVISION_TIMEOUT 	= b'\x19'
    WRITE_INQUIRY_MODE 				= b'\x1A'
    WRITE_EXTENDED_INQUIRY_RESPONSE = b'\x1B'
    READ_BD_ADDR 					= b'\x1C'
    READ_RSSI  						= b'\x1D'
    READ_AFH_CHANNEL_MAP  			= b'\x1E'
    ENABLE_DEVICE_UNDER_TEST_MODE  	= b'\x1F'
    WRITE_BT_ADDR  					= b'\x20'
    PASSKEY_ENTRY_RES  				= b'\x21'
    DISPLAY_YESNO_RES  				= b'\x22'
    WRITE_IAC_LAP  					= b'\x23'
    SET_CONNECTION_SECURITY         = b'\x24'
    SET_RF_MAX_TX_POWER             = b'\x25'
    READ_PAGE_SCAN_ACTIVITY         = b'\x26'
    READ_INQUIRY_SCAN_ACTIVITY      = b'\x27'
    READ_COD                        = b'\x28'
    WRITE_COD                       = b'\x29'
    SET_AFH                         = b'\x2A'
    READ_INQUIRY_SCAN_TYPE          = b'\x2B'
    READ_INQUIRY_MODE               = b'\x2C'
    READ_PAGE_SCAN_TYPE             = b'\x2D'
    WRITE_PAGE_SCAN_TYPE            = b'\x2E'
    READ_EIR                        = b'\x2F'
    READ_SC_HOST_SUPPORT            = b'\x30'
    WRITE_SC_HOST_SUPPORT           = b'\x31'
    READ_LINK_QUALITY               = b'\x32'
    QOS_SETUP                       = b'\x33'
    ROLE_DISCOVERY                  = b'\x34'
    READ_LINK_POLICY_SETTINGS       = b'\x35'
    READ_REMOTE_SUPPORTED_FEATURES  = b'\x36'
    READ_REMOTE_EXTENDED_FEATURES   = b'\x37'
    READ_REMOTE_VERSION_INFORMATION = b'\x38'
    SETUP_SYNCHRONOUS_CONNECTION    = b'\x39'
    ACCEPT_SYNCHRONOUS_CONNECTION   = b'\x3A'
    REJECT_SYNCHRONOUS_CONNECTION   = b'\x3B'
    PASSKEY_NEGATIVE_REPLY          = b'\x3C'
    SET_ACTIVE_SCO                  = b'\x3D'

class BT_GAP_Event_ID(enum.Enum):
    INQUIRY_COMPLETE                            = b'\x00'
    INQUIRY_RESULT                              = b'\x01'
    CONNECTED                                   = b'\x02'
    CONNECT_REQUEST                             = b'\x03'
    DISCONNECTED                                = b'\x04'
    AUTHENTICATION_COMPLETE                     = b'\x05'
    REMOTE_NAME_REQUEST_COMPLETE                = b'\x06'
    READ_REMOTE_SUPPORTED_FEATURES_COMPLETE     = b'\x07'
    READ_REMOTE_VERSION_INFORMATION_COMPLETE    = b'\x08'
    QOS_SETUP_COMPLETE                          = b'\x09'
    COMMAND_COMPLETE                            = b'\x0A'
    COMMAND_STATUS                              = b'\x0B'
    HARDWARE_ERROR                              = b'\x0C'
    ROLE_CHANGE                                 = b'\x0D'
    MODE_CHANGE                                 = b'\x0E'
    PIN_CODE_REQUEST                            = b'\x0F'
    CONNECTION_PACKET_TYPE_CHANGED              = b'\x10'
    INQUIRY_RESULT_RSSI                         = b'\x11'
    READ_REMOTE_EXTENDED_FEATURES_COMPLETE      = b'\x12'
    SYNCHRONOUS_CONNECTION_COMPLETE             = b'\x13'
    EX_INQUIRY_RESULT_RSSI                      = b'\x14'
    USER_CONFIRMATION_REQUEST                   = b'\x15'
    USER_PASSKEY_REQUEST                        = b'\x16'
    SIMPLE_PAIRING_COMPLETE                     = b'\x17'
    USER_PASSKEY_NOTIFICATION                   = b'\x18'
    KEYPRESS_NOTIFICATION                       = b'\x19'
    REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION = b'\x1A'
    MANU_SCO_ACTIVE_STATUS                      = b'\x1B'
    LINK_KEY_REQUEST                            = b'\x1C'
    LINK_KEY_NOTIFICATION                       = b'\x1D'
    ENCRYPT_STATUS                              = b'\x1E'

class BT_GAP_Cmd_Complete_ID(enum.Enum):
    INQUIRY_CANCEL                              = b'\x00'
    CREATE_CONNECTION_CANCEL                    = b'\x01'
    PIN_CODE_REQUEST_REPLY                      = b'\x02'
    PIN_CODE_REQUEST_NEGATIVE_REPLY             = b'\x03'
    REMOTE_NAME_REQUEST_CANCEL                  = b'\x04'
    USER_CONFIRMATION_REQUEST_REPLY             = b'\x05'
    USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY    = b'\x06'
    USER_PASSKEY_REQUEST_REPLY                  = b'\x07'
    USER_PASSKEY_REQUEST_NEGATIVE_REPLY         = b'\x08'
    ROLE_DISCOVERY                              = b'\x09'
    READ_LINK_POLICY_SETTINGS                   = b'\x0A'
    WRITE_LINK_POLICY_SETTINGS                  = b'\x0B'
    RESET                                       = b'\x0C'
    WRITE_LOCAL_NAME                            = b'\x0D'
    WRITE_PAGE_TIMEOUT                          = b'\x0E'
    WRITE_SCAN_ENABLE                           = b'\x0F'
    WRITE_PAGE_SCAN_ACTIVITY                    = b'\x10'
    WRITE_INQUIRY_SCAN_ACTIVITY                 = b'\x11'
    WRITE_CLASS_OF_DEVICE                       = b'\x12'
    SET_AFH_HOST_CHANNEL_CLASSIFICATION         = b'\x13'
    WRITE_INQUIRY_SCAN_TYPE                     = b'\x14'
    WRITE_INQUIRY_MODE                          = b'\x15'
    WRITE_PAGE_SCAN_TYPE                        = b'\x16'
    WRITE_EXTENDED_INQUIRY_RESPONSE             = b'\x17'
    READ_LOCAL_NAME                             = b'\x18'
    READ_PAGE_TIMEOUT                           = b'\x19'
    READ_SCAN_ENABLE                            = b'\x1A'
    READ_PAGE_SCAN_ACTIVITY                     = b'\x1B'
    READ_INQUIRY_SCAN_ACTIVITY                  = b'\x1C'
    READ_CLASS_OF_DEVICE                        = b'\x1D'
    READ_LINK_SUPERVISION_TIMEOUT               = b'\x1E'
    WRITE_LINK_SUPERVISION_TIMEOUT              = b'\x1F'
    READ_INQUIRY_SCAN_TYPE                      = b'\x20'
    READ_INQUIRY_MODE                           = b'\x21'
    READ_PAGE_SCAN_TYPE                         = b'\x22'
    READ_EXTENDED_INQUIRY_RESPONSE              = b'\x23'
    SEND_KEYPRESS_NOTIFICATION                  = b'\x24'
    READ_BD_ADDR                                = b'\x25'
    READ_RSSI                                   = b'\x26'
    READ_AFH_CHANNEL_MAP                        = b'\x27'
    ENABLE_DEVICE_UNDER_TEST_MODE               = b'\x28'
    WRITE_BT_ADDR                               = b'\x29'
    READ_SECURE_CONNECTIONS_HOST_SUPPORT        = b'\x2A'
    WRITE_SECURE_CONNECTIONS_HOST_SUPPORT       = b'\x2B'
    READ_LINK_QUILITY                           = b'\x2C'
    WRITE_CURRENT_IAC_LAP                       = b'\x2D'
    SET_RF_MAX_TX_POWER                         = b'\x2E'

class BT_GAP_Cmd_Status_ID(enum.Enum):
    INQUIRY                                     = b'\x00'
    CREATE_CONNECTION                           = b'\x01'
    DISCONNECT                                  = b'\x02'
    ACCEPT_CONNECTION_REQUEST                   = b'\x03'
    REJECT_CONNECTION_REQUEST                   = b'\x04'
    CHANGE_CONNECTION_PACKET_TYPE               = b'\x05'
    REMOTE_NAME_REQUEST                         = b'\x06'
    READ_REMOTE_SUPPORTED_FEATURES              = b'\x07'
    READ_REMOTE_EXTENDED_FEATURES               = b'\x08'
    READ_REMOTE_VERSION_INFORMATION             = b'\x09'
    SETUP_SYNCHRONOUS_CONNECTION                = b'\x0A'
    ACCEPT_SYNCHRONOUS_CONNECTION               = b'\x0B'
    REJECT_SYNCHRONOUS_CONNECTION               = b'\x0C'
    SNIFF_MODE                                  = b'\x0D'
    EXIT_SNIFF_MODE                             = b'\x0E'
    QOS_SETUP                                   = b'\x0F'
    ROLE_SWITCH                                 = b'\x10'

class BT_GAP_Status_ID(enum.Enum):
    SUCCESS                                     = b'\x00'
    UNKNOWN_HCI_COMMAND                         = b'\x01'
    UNKNOWN_CONNECTION_IDENTIFIER               = b'\x02'
    HARDWARE_FAILURE                            = b'\x03'
    PAGE_TIMEOUT                                = b'\x04'
    AUTHENTICATION_FAILURE                      = b'\x05'
    PIN_KEY_MISSING                             = b'\x06'
    MEMORY_CAPACITY_EXCEEDED                    = b'\x07'
    CONNECTION_TIMEOUT                          = b'\x08'
    CONNECTION_LIMIT_EXCEEDED                   = b'\x09'
    SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED       = b'\x0A'
    CONNECTION_ALREADY_EXISTS                   = b'\x0B'
    COMMAND_DISALLOWED                          = b'\x0C'
    REJECTED_DUE_TO_LIMITED_RESOURCES           = b'\x0D'
    REJECTED_DUE_TO_SECURITY_REASONS            = b'\x0E'
    REJECTED_DUE_TO_UNACCEPTABLE_BDADDR         = b'\x0F'
    CONNECTION_ACCEPT_TIMEOUT                   = b'\x10'
    UNSUPPORTED_FEATURE                         = b'\x11'
    INVALID_HCI_COMMAND_PARAMETERS              = b'\x12'
    REMOTE_TERMINATE_CONNECTION                 = b'\x13'
    REMOTE_TERMINATE_CONNECTION_LOW_RESOURCE    = b'\x14'
    REMOTE_TERMINATE_CONNECTION_POWEROFF        = b'\x15'
    LOCAL_HOST_TERMINATE_CONNECTION             = b'\x16'
    REPEATED_ATTEMPTS                           = b'\x17'
    PAIRING_NOT_ALLOWED                         = b'\x18'
    UNKNOWN_LMP_PDU                             = b'\x19'
    UNSUPPORTED_REMOTE_FEATURE                  = b'\x1A'
    SCO_OFFSET_REJECT                           = b'\x1B'
    SCO_INTEVAL_REJECT                          = b'\x1C'
    SCO_AIR_MODE_REJECT                         = b'\x1D'
    INVALID_LMP_PARAMETERS                      = b'\x1E'
    UNSPECIFIED_ERROR                           = b'\x1F'
    UNSUPPORTED_LMP_PARAMETERS                  = b'\x20'
    ROLE_CHANGE_NOT_ALLOW                       = b'\x21'
    LMP_RESPONSE_TIMEOUT                        = b'\x22'
    LMP_ERROR_TRANSACTION_COLLISION             = b'\x23'
    LMP_PDU_NOT_ALLOW                           = b'\x24'
    ENCRYPTION_MODE_NOT_ACCEPTABLE              = b'\x25'
    LINK_KEY_CANNOT_BE_CHANGED                  = b'\x26'
    REQUESTED_QOS_NOT_SUPPORT                   = b'\x27'
    INSTANT_PASSED                              = b'\x28'
    PAIRING_WITH_UNIT_KEY_NOT_SUPPORT           = b'\x29'
    DIFFERENT_TRANSACTION_COLLISION             = b'\x2A'
    RESERVED_FOR_FUTURE_USE1                    = b'\x2B'
    QOS_UNACCEPTABLE_PARAMETER                  = b'\x2C'
    QOS_REJECTED                                = b'\x2D'
    CHANNEL_CLASSIFICATION_NOT_SUPPORT          = b'\x2E'
    INSUFFICIENT_SECURITY                       = b'\x2F'
    PARAMETER_OUT_OF_MANDATORY_RANGE            = b'\x30'
    RESERVED_FOR_FUTURE_USE2                    = b'\x31'
    ROLE_SWITCH_PENDING                         = b'\x32'
    RESERVED_FOR_FUTURE_USE3                    = b'\x33'
    RESERVED_SLOT_VIOLATION                     = b'\x34'
    ROLE_SWITCH_FAILED                          = b'\x35'
    EXTENDED_INQUIRY_RESPONSE_TOO_LARGE         = b'\x36'
    SECURE_SIMPLE_PAIRING_NOT_SUPPORT           = b'\x37'
    HOST_BUSY_PAIRING                           = b'\x38'
    CONNECTION_REJECT_NON_SUITABLE_CHANNEL      = b'\x39'
    CONTROLLER_BUSY                             = b'\x3A'
    UNACCEPTABLE_CONNECTION_PARAMETERS          = b'\x3B'
    ADVERTISING_TIMEOUT                         = b'\x3C'
    CONNECTION_TERMINATE_MIC_FAILURE            = b'\x3D'
    CONNECTION_FAILED_TO_BE_ESTABLISHED         = b'\x3E'
    MAC_CONNECTION_FAILED                       = b'\x3F'
    COARSE_CLOCK_ADJUSTMENT_REJECTED            = b'\x40'
    TYPE0_SUBMAP_NOT_DEFINED                    = b'\x41'
    UNKNOWN_ADVERTISING_IDENTIFIER              = b'\x42'
    LIMIT_REACHED                               = b'\x43'
    OPERATION_CANCELLED_BY_HOST                 = b'\x44'

class BT_GAP_SECURITY(enum.Enum):
    MODE_1 = b'\x00'
    MODE_2 = b'\x01'
    MODE_3 = b'\x02'
    MODE_4 = b'\x03'

class BT_GAP_LAP(enum.Enum):
    LIAC = b'\x00\x8B\x9E'
    GIAC = b'\x33\x8B\x9E'

class BT_GAP_INQUIRY_TIME(enum.Enum):
    MIN = b'\x01'
    MAX = b'\x30'

class BT_GAP_SCAN_ENABLE(enum.Enum):
    INQUIRY_SCAN_NO_SCAN_ENABLED          = b'\x00'
    INQUIRY_SCAN_ENABLE_PAGE_SCAN_DISABLE = b'\x01'
    INQUIRY_SCAN_DISABLE_PAGE_SCAN_ENABLE = b'\x02'
    INQUIRY_SCAN_ENABLE_PAGE_SCAN_ENABLE  = b'\x03'

class BT_GAP_PAGE_SCAN_REPETITION(enum.Enum):
    R0 = b'\x00'
    R1 = b'\x01'
    R2 = b'\x02'

class BT_GAP_AUTH_REQUIREMENT(enum.Enum):
    MITM_NOT_REQUIRED_NO_BONDING        = b'\x00'  # MITM is not required and no bonding.
    MITM_REQUIRED_NO_BONDING            = b'\x01'  # MITM is required and no bonding.
    MITM_NOT_REQUIRED_DEDICATED_BONDING = b'\x02'  # MITM is not required and dedicated bonding.
    MITM_REQUIRED_DEDICATED_BONDING     = b'\x03'  # MITM is required and dedicated bonding.
    MITM_NOT_REQUIRED_GENERAL_BONDING   = b'\x04'  # MITM is not required and general bonding
    MITM_REQUIRED_GENERAL_BONDING       = b'\x05'  # MITM is required and general bonding.

class BT_GAP_IOCAPABILITY(enum.Enum):
    DISPLAYONLY     = b'\x00'
    DISPLAYYESNO    = b'\x01'
    KEYBOARDONLY    = b'\x02'
    NOINPUTNOOUTPUT = b'\x03'

class BT_GAP_DISC_REASON(enum.Enum):
    AUTH_FAIL             = b'\x05'
    REMOTE_TERMINATE      = b'\x13'
    LOW_RESOURCES         = b'\x14'
    POWER_OFF             = b'\x15'
    UNSUPPORTED           = b'\x1A'
    KEY_LEN_UNSUPPORTED   = b'\x29'
    UNACCEPTABLE_CP       = b'\x3B'

class BT_GAP_PACKET_TYPE(enum.Enum):
    ACL_2DH1 = b'\x00\x02'
    ACL_3DH1 = b'\x00\x04'
    ACL_DM1  = b'\x00\x08'
    ACL_DH1  = b'\x00\x10'
    SCO_HV1  = b'\x00\x20'
    SCO_HV2  = b'\x00\x40'
    SCO_HV3  = b'\x00\x80'
    ACL_2DH3 = b'\x01\x00'
    ACL_3DH3 = b'\x02\x00'
    ACL_DM3  = b'\x04\x00'
    ACL_DH3  = b'\x08\x00'
    ACL_2DH5 = b'\x10\x00'
    ACL_3DH5 = b'\x20\x00'
    ACL_DM5  = b'\x40\x00'
    ACL_DH5  = b'\x80\x00'

class BT_GAP_SYNC_CONN_MAX_LATENCY(enum.Enum):
    LATENCY_MIN = b'\x00\x04'
    LATENCY_MAX = b'\xFF\xFE'

class BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT(enum.Enum):
    NO        = b'\x00'
    OPT_PS    = b'\x01'
    OPT_LQ    = b'\x02'
    DONT_CARE = b'\xFF'

class BT_GAP_SYNC_CONN_PACKET_TYPE(enum.Enum):
    TYPE_HV1  = b'\x00\x01'
    TYPE_HV2  = b'\x00\x02'
    TYPE_HV3  = b'\x00\x04'
    TYPE_EV3  = b'\x00\x08'
    TYPE_EV4  = b'\x00\x10'
    TYPE_EV5  = b'\x00\x20'
    TYPE_2EV3 = b'\x00\x40'
    TYPE_3EV3 = b'\x00\x80'
    TYPE_2EV5 = b'\x01\x00'
    TYPE_3EV5 = b'\x02\x00'

class BT_GAP_LINK_TYPE(enum.Enum):
    SCO  = b'\x00'
    ACL  = b'\x01'
    ESCO = b'\x02'
# endregion

# region BLE GATT
class GATT_CMD_ID(enum.Enum):
    READ                   = b'\x00'
    WRITE                  = b'\x01'
    HANDLE_CONF            = b'\x02'
    EX_MTU                 = b'\x03'
    DIS_ALL_PSERV          = b'\x04'
    DIS_PRIMARY_SERV_UUID  = b'\x05'
    DIS_ALL_CHAR           = b'\x06'
    DIS_ALL_DESC           = b'\x07'
    READ_USING_UUID        = b'\x08'
    SEND_HANDLE_VALUE      = b'\x09'
    SET_HANDLE_VALUE       = b'\x0A'
    SEND_READ_RESP         = b'\x0B'
    SEND_ERR_RESP          = b'\x0C'
    SEND_READ_BY_TYPE_RESP = b'\x0D'
    SEND_PREP_WRITE_RESP   = b'\x0E'
    BT_CONNECT             = b'\x0F'
    BT_DISCONNECT          = b'\x10'
    DIS_CHAR_USING_UUID    = b'\x11'
    SERVICE_CHANGE         = b'\x12'
    ADD_SERVICE            = b'\x13'
    REMOVE_SERVICE         = b'\x14'
    READ_MULTI_VARIABLE    = b'\x15'
    MULTI_HANDLE_VALUE_NTF = b'\x16'
    GET_ATTRIBUTE_VALUE    = b'\x17'
    TEST                   = b'\x18'
    SET_PREFERRED_MTU      = b'\x19'

class GATT_Event_ID(enum.Enum):
    ERROR_RESP                  = b'\x00'
    DISC_PRIM_SERV_RESP         = b'\x01'
    DISC_PRIM_SERV_BY_UUID_RESP = b'\x02'
    DISC_CHAR_RESP              = b'\x03'
    DISC_DESC_RESP              = b'\x04'
    READ_USING_UUID_RESP        = b'\x05'
    READ_RESP                   = b'\x06'
    WRITE_RESP                  = b'\x07'
    HV_NOTIFY                   = b'\x08'
    HV_INDICATE                 = b'\x09'
    READ                        = b'\x0A'
    WRITE                       = b'\x0B'
    HV_CONFIRM                  = b'\x0C'
    RESERVED1                   = b'\x0D'
    TIMEOUT                     = b'\x0E'
    UPDATE_MTU                  = b'\x0F'
    BT_CONNECT_COMPLETE_CFM     = b'\x10'
    BT_DISCONNECT_CFM           = b'\x11'
    RESERVED2                   = b'\x12'
    DISC_CHAR_BY_UUID_RESP      = b'\x13'
    SERVICE_CHANGE              = b'\x14'
    RESERVED3                   = b'\x15'
    RESERVED4                   = b'\x16'
    CLIENT_FEATURE_CHANGE       = b'\x17'
    CLIENT_CCCDLIST_CHANGE      = b'\x18'
    PROTOCOL_AVAILABLE          = b'\x19'

class GATT_MTU_LENGTH(enum.Enum):
    DEFAULT_MTU_LEN = 23
    MAX_MTU_LEN     = 247

class GATT_HEADER_SIZE(enum.Enum):
    HANDLE_VALUE       = 3       # The BLE ATT Handle Value Notification/Indication Header Size
    WRITE              = 3       # The BLE ATT Write Request/Command Header Size
    READ_RESP          = 1       # The BLE ATT Read Response Header Size.
    WRITE_RESP         = 5       # The BLE ATT Prepare Write Response Header Size.
    FIND_INFO_RESP     = 2       # The ATT Find Information Response Header Size.
    FIND_BY_TYPE_RESP  = 1       # The ATT Find By Type Value Response Header Size.
    READ_BY_TYPE_RESP  = 2       # The ATT Read By Type Response Header Size. */
    READ_BY_GROUP_RESP = 2       # The ATT Read By Group Type Response Header Size. */
    PREP_WRITE_RESP    = 5       # The ATT Prepare Write Response Header Size. */
    NOTI_INDI          = 3       # The ATT Notification/Indication Header Size. */

class GATT_SEND_HV_TYPES(enum.Enum):
    HV_NOTIFICATION = b'\x1B'
    HV_INDICATION   = b'\x1D'

class GATT_READ_TYPES(enum.Enum):
    READ_REQ      = b'\x01'
    READ_BLOB_REQ = b'\x02'

class GATT_READ_RESP_TYPES(enum.Enum):
    READ_RESP      = b'\x0B'
    READ_BLOB_RESP = b'\x0D'

class GATT_WRITE_TYPES(enum.Enum):
    WRITE_REQ      = b'\x12'
    WRITE_CMD      = b'\x52'
    PREP_WRITE_REQ = b'\x16'
    EXEC_WRITE_REQ = b'\x18'

class GATT_WRITE_RESP_TYPES(enum.Enum):
    WRITE_RESP      = b'\x13'
    PREP_WRITE_RESP = b'\x17'
    EXEC_WRITE_RESP = b'\x19'

class GATT_EXEC_WRITE_FLAGS(enum.Enum):
    CANCEL_ALL = b'\x00'
    WRITE      = b'\x01'

class GATT_ERROR_CODES(enum.Enum):
    INVALID_HANDLE                   = b'\x01'
    READ_NOT_PERMITTED               = b'\x02'
    WRITE_NOT_PERMITTED              = b'\x03'
    INVALID_PDU                      = b'\x04'
    INSUFFICIENT_AUTHENTICATION      = b'\x05'
    REQUEST_NOT_SUPPORT              = b'\x06'
    INVALID_OFFSET                   = b'\x07'
    INSUFFICIENT_AUTHORIZATION       = b'\x08'
    PREPARE_QUEUE_FULL               = b'\x09'
    ATTRIBUTE_NOT_FOUND              = b'\x0A'
    ATTRIBUTE_NOT_LONG               = b'\x0B'
    INSUFFICIENT_ENCRYPTION_KEY_SIZE = b'\x0C'
    INVALID_ATTRIBUTE_VALUE_LENGTH   = b'\x0D'
    UNLIKELY_ERROR                   = b'\x0E'
    INSUFFICIENT_ENCRYPTION          = b'\x0F'
    UNSUPPORTED_GROUP_TYPE           = b'\x10'
    INSUFFICIENT_RESOURCE            = b'\x11'
    APPLICATION_ERROR                = b'\x80'

class GATT_OPCODES(enum.Enum):
    ERROR_RESPONSE              = b'\x01'
    EXCHANGE_MTU_REQUEST        = b'\x02'
    EXCHANGE_MTU_RESPONSE       = b'\x03'
    FIND_INFORMATION_REQUEST    = b'\x04'
    FIND_INFORMATION_RESPONSE   = b'\x05'
    FIND_BY_TYPE_VALUE_REQUEST  = b'\x06'
    FIND_BY_TYPE_VALUE_RESPONSE = b'\x07'
    READ_BY_TYPE_REQUEST        = b'\x08'
    READ_BY_TYPE_RESPONSE       = b'\x09'
    READ_REQUEST                = b'\x0A'
    READ_RESPONSE               = b'\x0B'
    READ_BLOB_REQUEST           = b'\x0C'
    READ_BLOB_RESPONSE          = b'\x0D'
    READ_MULTIPLE_REQUEST       = b'\x0E'
    READ_MULTIPLE_RESPONSE      = b'\x0F'
    READ_BY_GROUP_TYPE_REQUEST  = b'\x10'
    READ_BY_GROUP_TYPE_RESPONSE = b'\x11'
    WRITE_REQUEST               = b'\x12'
    WRITE_RESPONSE              = b'\x13'
    WRITE_COMMAND               = b'\x52'
    PREPARE_WRITE_REQUEST       = b'\x16'
    PREPARE_WRITE_RESPONSE      = b'\x17'
    EXECUTE_WRITE_REQUEST       = b'\x18'
    EXECUTE_WRITE_RESPONSE      = b'\x19'
    HANDLE_VALUE_NOTIFICATION   = b'\x1B'
    HANDLE_VALUE_INDICATION     = b'\x1D'
    HANDLE_VALUE_CONFIRMATION   = b'\x1E'
    SIGNED_WRITE_COMMAND        = b'\xD2'

class GATT_PROCEDURE_STATUS(enum.Enum):
    CONTINUE = b'\x00'
    FINISH   = b'\x01'

# endregion

# region BLE GAP
class BLE_GAP_CMD_ID(enum.Enum):
    SET_ADDR                      = b'\x00'
    GEN_GET_ADDR                  = b'\x01'
    GET_DEV_NAME                  = b'\x02'
    SET_DEV_NAME                  = b'\x03'
    SET_ADV_DATA                  = b'\x04'
    SET_SCAN_RESP_DATA            = b'\x05'
    SET_ADV_PARAM                 = b'\x06'
    ADV_ENABLE                    = b'\x07'
    TERMINATE_CONNECTION          = b'\x08'
    UPDATE_CONN_PARA              = b'\x09'
    GET_RSSI                      = b'\x0A'
    READ_WHITE_LIST_SIZE          = b'\x0B'
    CLEAR_WHITE_LIST              = b'\x0C'
    ADD_WHITE_LIST                = b'\x0D'
    REMOVE_WHITE_LIST             = b'\x0E'
    ADD_DEVICE_TO_RESOLVING_LIST  = b'\x0F'
    CLEAR_RESOLVING_LIST          = b'\x10'
    READ_LOCAL_RESOLVABLE_ADDRESS = b'\x11'
    SET_ADDRESS_RESOLUTION_ENABLE = b'\x12'
    CREATE_CONNECTION			  = b'\x13'
    CREATE_CONNECTION_CANCEL      = b'\x14'
    SET_SCANNING_PARAM            = b'\x15'
    SET_SCANNING_ENABLE           = b'\x16'
    WRITE_BEACON_PARA             = b'\x17'
    WRITE_BEACON_DATA             = b'\x18'
    WRITE_BEACON_ENABLE           = b'\x19'
    CHANGE_TX_BUFFER_SIZE_MODE    = b'\x1A'
    WRITE_BEACON_RANDOM_ADDRESS   = b'\x1B'
    RECEIVER_TEST				  = b'\x1C'
    TRANSMITTER_TEST              = b'\x1D'
    END_TEST                      = b'\x1E'
    SET_RF_MAX_TX_POWER           = b'\x1F'
    SET_CHANNEL_MAP               = b'\x20'
    START_ENCRYPTION              = b'\x21'
    SET_EXT_ADV_PARAM             = b'\x22'
    SET_EXT_ADV_DATA              = b'\x23'
    SET_EXT_SCAN_RESP_DATA        = b'\x24'
    SET_EXT_ADV_ENABLE            = b'\x25'
    SET_PERIODIC_ADV_PARAM        = b'\x26'
    SET_PERIODIC_ADV_DATA         = b'\x27'
    SET_PERIODIC_ADV_ENABLE       = b'\x28'
    SET_EXT_SCAN_PARAM            = b'\x29'
    SET_EXT_SCAN_ENABLE           = b'\x2A'

class BLE_GAP_Event_ID(enum.Enum):
    CONNECTED                     = b'\x00'
    DISCONNECTED                  = b'\x01'
    CONN_PARA_UPDATE              = b'\x02'
    ENCRYPT_STATUS                = b'\x03'
    COMMAND_COMPLETE              = b'\x04'
    COMMAND_STATUS                = b'\x05'
    ADVERTISING_REPORT            = b'\x06'
    HARDWARE_ERROR                = b'\x07'
    LONG_TERM_KEY_REQUEST         = b'\x08'
    REMOTE_CONN_PARAM_REQUEST     = b'\x09'
    DATA_LENGTH_CHANGE            = b'\x0A'
    EXT_ADVERTISING_REPORT        = b'\x0B'
    ADVERTISING_TIMEOUT           = b'\x0C'
    TX_BUF_AVAILABLE              = b'\x0D'
    READ_REMOTE_FEATURES          = b'\x0E'

class BLE_GAP_Cmd_Complete_ID(enum.Enum):
    SET_RANDOM_ADDRESS              = b'\x00'
    SET_ADVERTISING_DATA            = b'\x01'
    SET_SCAN_RESPONSE_DATA          = b'\x02'
    SET_ADVERTISING_PARAMS          = b'\x03'
    SET_ADVERTISING_ENABLE          = b'\x04'
    SET_RF_MAX_TX_POWER             = b'\x05'
    CLEAR_WHITE_LIST                = b'\x06'
    ADD_WHITE_LIST                  = b'\x07'
    REMOVE_WHITE_LIST               = b'\x08'
    ADD_DEVICE_TO_RESOLVING_LIST    = b'\x09'
    CLEAR_RESOLVING_LIST            = b'\x0A'
    READ_LOCAL_RESOLVABLE_ADDRESS   = b'\x0B'
    SET_ADDRESS_RESOLUTION_ENABLE   = b'\x0C'
    SET_SCAN_PARAMS                 = b'\x0D'
    SET_SCAN_ENABLE                 = b'\x0E'
    CREATE_CONNECTION_CANCEL        = b'\x0F'
    SET_HOST_CH_CLASS               = b'\x10'
    WRITE_BEACON_PARAMS             = b'\x11'
    WRITE_BEACON_DATA               = b'\x12'
    WRITE_BEACON_ENABLE             = b'\x13'
    WRITE_BEACON_ADDR               = b'\x14'
    RECEIVER_TEST                   = b'\x15'
    TRANSMITTER_TEST                = b'\x16'
    END_TEST                        = b'\x17'
    LTK_REQ_REPLY                   = b'\x18'
    LTK_REQ_NEGATIVE_REPLY          = b'\x19'
    CONN_PARAM_REQ_REPLY            = b'\x1A'
    CONN_PARAM_REQ_NEGATIVE_REPLY   = b'\x1B'
    READ_WHITE_LIST_SIZE            = b'\x1C'
    READ_RSSI                       = b'\x1D'
    SET_EXT_ADVERTISING_PARAMS      = b'\x1E'
    SET_EXT_ADVERTISING_DATA        = b'\x1F'
    SET_EXT_SCAN_RESPONSE_DATA      = b'\x20'
    SET_EXT_ADVERTISING_ENABLE      = b'\x21'
    SET_PERIODIC_ADVERTISING_PARAMS = b'\x22'
    SET_PERIODIC_ADVERTISING_DATA   = b'\x23'
    SET_PERIODIC_ADVERTISING_ENABLE = b'\x24'
    SET_EXT_SCANNING_PARAMS         = b'\x25'
    SET_EXT_SCANNING_ENABLE         = b'\x26'
    READ_BD_ADDR                    = b'\x27'

class BLE_GAP_Cmd_Status_ID(enum.Enum):
    CREATE_CONNECTION             = b'\x00'
    CONNECTION_UPDATE             = b'\x01'
    START_ENCRYPTION              = b'\x02'

class BLE_GAP_SCAN(enum.Enum):
    DISABLE                   = b'\x00'
    ENABLE                    = b'\x01'
    TYPE_PASSIVE_SCAN         = b'\x00'
    TYPE_ACTIVE_SCAN          = b'\x01'
    FILTER_POLICY_DEFAULT     = b'\x00'
    FILTER_POLICY_WHITELIST   = b'\x01'
    FILTER_DUPLICATES_DISABLE = b'\x00'
    FILTER_DUPLICATES_ENABLE  = b'\x01'
    MODE_GENERAL_DISCOVERY    = b'\x00'
    MODE_LIMITED_DISCOVERY    = b'\x01'
    MODE_OBSERVER             = b'\x02'

class BLE_GAP_ADV(enum.Enum):
    ENABLE                                              = b'\x01'
    DISABLE                                             = b'\x00'
    TYPE_ADV_IND                                        = b'\x00'        # Connectable undirected advertising
    TYPE_ADV_DIRECT_IND                                 = b'\x01'        # Connectable high duty cycle directed advertising
    TYPE_ADV_SCAN_IND                                   = b'\x02'        # Scannable undirected advertising
    TYPE_ADV_NONCONN_IND                                = b'\x03'        # Non connectable undirected advertising
    TYPE_ADV_DIRECT_IND_LOW                             = b'\x04'        # Connectable low duty cycle directed advertising
    EVENTTYPE_ADV_IND                                   = b'\x00'
    EVENTTYPE_ADV_DIRECT_IND                            = b'\x01'
    EVENTTYPE_ADV_SCAN_IND                              = b'\x02'
    EVENTTYPE_ADV_NONCONN_IND                           = b'\x03'
    EVENTTYPE_ADV_SCAN_RSP                              = b'\x04'
    DATATYPE_Flags                                      = b'\x01'
    DATATYPE_Incomplete_List_16bit_Service_Class_UUIDs  = b'\x02'
    DATATYPE_Complete_List_16bit_Service_Class_UUIDs    = b'\x03'
    DATATYPE_Incomplete_List_32bit_Service_Class_UUIDs  = b'\x04'
    DATATYPE_Complete_List_32bit_Service_Class_UUIDs    = b'\x05'
    DATATYPE_Incomplete_List_128bit_Service_Class_UUIDs = b'\x06'
    DATATYPE_Complete_List_128bit_Service_Class_UUIDs   = b'\x07'
    DATATYPE_Shortened_Local_Name                       = b'\x08'
    DATATYPE_Complete_Local_Name                        = b'\x09'
    DATATYPE_Tx_Power_Level                             = b'\x0A'
    DATATYPE_Class_of_Device                            = b'\x0D'
    DATATYPE_Simple_Pairing_Hash_C                      = b'\x0E'
    DATATYPE_Simple_Pairing_Hash_C_192                  = b'\x0E'
    DATATYPE_Simple_Pairing_Randomizer_R                = b'\x0F'
    DATATYPE_Simple_Pairing_Randomizer_R_192            = b'\x0F'
    DATATYPE_Device_ID                                  = b'\x10'
    DATATYPE_Security_Manager_TK_Value                  = b'\x10'
    DATATYPE_Security_Manager_Out_of_Band_Flags         = b'\x11'
    DATATYPE_Slave_Connection_Interval_Range            = b'\x12'
    DATATYPE_List_16bit_Solicitation_UUIDs              = b'\x14'
    DATATYPE_List_128bit_Service_Solicitation_UUIDs     = b'\x15'
    DATATYPE_Service_Data                               = b'\x16'
    DATATYPE_Service_Data_16bit_UUID                    = b'\x16'
    DATATYPE_Public_Target_Address                      = b'\x17'
    DATATYPE_Random_Target_Address                      = b'\x18'
    DATATYPE_Appearance                                 = b'\x19'
    DATATYPE_Advertising_Interval                       = b'\x1A'
    DATATYPE_LE_Bluetooth_Device_Address                = b'\x1B'
    DATATYPE_LE_Role                                    = b'\x1C'
    DATATYPE_Simple_Pairing_Hash_C_256                  = b'\x1D'
    DATATYPE_Simple_Pairing_Randomizer_R_256            = b'\x1E'
    DATATYPE_List_32bit_Service_Solicitation_UUIDs      = b'\x1F'
    DATATYPE_Service_Data_32bit_UUID                    = b'\x20'
    DATATYPE_Service_Data_128bit_UUID                   = b'\x21'
    DATATYPE_LE_Secure_Connections_Confirmation_Value   = b'\x22'
    DATATYPE_LE_Secure_Connections_Random_Value         = b'\x23'
    DATATYPE_URI                                        = b'\x24'
    DATATYPE_Indoor_Positioning                         = b'\x25'
    DATATYPE_Transport_Discovery_Data                   = b'\x26'
    DATATYPE_LE_Supported_Features                      = b'\x27'
    DATATYPE_Channel_Map_Update_Indication              = b'\x28'
    DATATYPE_PB_ADV                                     = b'\x29'
    DATATYPE_Mesh_Message                               = b'\x2A'
    DATATYPE_Mesh_Beacon                                = b'\x2B'
    DATATYPE_Information_Data_3D                        = b'\x3D'
    DATATYPE_Manufacturer_Specific_Data                 = b'\xFF'
    Flags_Non_Discover                                  = b'\x00'
    Flags_Limited_Discover                              = b'\x01'
    Flags_General_Discover                              = b'\x02'
    Flags_LE_Non_Discover                               = b'\x04'
    Flags_LE_Limited_Discover                           = b'\x05'
    Flags_LE_General_Discover                           = b'\x06'
    Flags_BRLE_Non_Discover_Control                     = b'\x08'
    Flags_BRLE_Limited_Discover_Control                 = b'\x09'
    Flags_BRLE_General_Discover_Control                 = b'\x0A'
    Flags_BRLE_Non_Discover_Host                        = b'\x10'
    Flags_BRLE_Limited_Discover_Host                    = b'\x11'
    Flags_BRLE_General_Discover_Host                    = b'\x12'
    Flags_BRLE_Non_Discover_CnH                         = b'\x18'
    Flags_BRLE_Limited_Discover_CnH                     = b'\x19'
    Flags_BRLE_General_DiscoverCH_CnH                   = b'\x1A'
    CHANNEL_37                                          = b'\x01'
    CHANNEL_38                                          = b'\x02'
    CHANNEL_39                                          = b'\x04'
    CHANNEL_ALL                                         = b'\x07'
    FILTER_POLICY_DEFAULT                               = b'\x00'
    FILTER_POLICY_SCAN                                  = b'\x01'
    FILTER_POLICY_CONNECT                               = b'\x02'
    FILTER_POLICY_SCAN_CONNECT                          = b'\x03'
    MAX_LENGTH                                          = b'\x1F'

class BLE_GAP_ADDR_TYPE(enum.Enum):
    PUBLIC                        = b'\x00'
    RANDOM_STATIC                 = b'\x01'
    RANDOM_PRIVATE_RESOLVABLE     = b'\x02'
    RANDOM_PRIVATE_NON_RESOLVABLE = b'\x03'

class BLE_GAP_DISC_REASON(enum.Enum):
    AUTH_FAIL           = b'\x05'
    REMOTE_TERMINATE    = b'\x13'
    LOW_RESOURCES       = b'\x14'
    POWER_OFF           = b'\x15'
    UNSUPPORTED         = b'\x1A'
    KEY_LEN_UNSUPPORTED = b'\x29'
    UNACCEPTABLE_CP     = b'\x3B'
# endregion

# region BLE SMP
class SMP_CMD_ID(enum.Enum):
    CONFIG              = b'\x00'
    PASSKEY_REPLY       = b'\x01'
    PASSKEY_NEG_REPLY   = b'\x02'
    NUM_COMP_CONF_REPLY = b'\x03'
    INIT_PAIR           = b'\x04'
    GEN_PASSKEY         = b'\x05'
    SET_PRIVACY_KEY     = b'\x06'
    ENABLE_DEBUG_MODE   = b'\x07'
    GEN_OOB_DATA        = b'\x08'
    SET_LESC_OOB_DATA   = b'\x09'

class SMP_Event_ID(enum.Enum):
    PAIRING_COMPLETE                   = b'\x00'
    SECURITY_REQUEST                   = b'\x01'
    NUMERIC_COMPARISON_CONFIRM_REQUEST = b'\x02'
    INPUT_PASSKEY                      = b'\x03'
    DISPLAY_PASSKEY_REQUEST            = b'\x04'
    NOTIFY_KEYS                        = b'\x05'
    PAIRING_REQUEST                    = b'\x06'
    INPUT_OOB_DATA_REQUEST             = b'\x07'

class SMP_IoCapability(enum.Enum):
    DISPLAYONLY     = b'\x00'
    DISPLAYYESNO    = b'\x01'
    KEYBOARDONLY    = b'\x02'
    NOINPUTNOOUTPUT = b'\x03'
    KEYBOARDDISPLAY = b'\x04'

class SMP_AuthReqFlag(enum.Enum):
    NOBONDING      = b'\x00'
    BONDING        = b'\x01'
    MITM	       = b'\x04'
    BONDINGMITM    = b'\x05'
    SECCNT         = b'\x08'
    BONDSECCNT     = b'\x09'
    MITMSECCNT     = b'\x0C'
    SECCNTBONDMITM = b'\x0D'

class SMP_SECURE_SET(enum.Enum):
    NOSECURE = b'\x00'
    SECURE   = b'\x01'

class SMP_OOB(enum.Enum):
    NOT_PRESENT = b'\x00'
    PRESENT     = b'\x01'
# endregion

# region BLE TRS
class TRS_CMD_ID(enum.Enum):
    DEINITIALIZE          = b'\x00'
    ENABLE_DATA_SESSION   = b'\x01'
    DISABLE_DATA_SESSION  = b'\x02'
    SEND_TRANSPARENT_DATA = b'\x03'
    GET_DATA              = b'\x04'
    CHANGE_UUID           = b'\x05'
    PERMISSION_CONFIG     = b'\x06'

class TRS_Event_ID(enum.Enum):
     CONNECTED    = b'\x00'
     RECEIVE_DATA = b'\x01'

class TRS_creditBaseCtrl(enum.Enum):
    DISABLE = b'\x00'
    ENABLE  = b'\x01'

class TRS_ROLE(enum.Enum):
    SERVER = b'\x00'
    CLIENT = b'\x01'
# endregion

# region BT HFP
class HFP_CMD_ID(enum.Enum):
    CONNECT_REQ              = b'\x00'
    DISCONNECT_REQ           = b'\x01'
    AUDIO_TRANSFER_REQ       = b'\x02'
    CALL_ANSWER_ACCEPT       = b'\x03'
    CALL_ANSWER_REJECT       = b'\x04'
    CALL_TERMINATE           = b'\x05'
    CURRENT_CALL_REQ         = b'\x06'
    CALL_WAITING_ENABLE      = b'\x07'
    CALLERID_ENABLE          = b'\x08'
    CALL_HOLD_ACTION_REQ     = b'\x09'
    RESPONSE_HOLD_REQ        = b'\x0A'
    DIAL_LAST_NUMBER         = b'\x0B'
    DIAL_NUMBER              = b'\x0C'
    DIAL_MEMORY              = b'\x0D'
    VOICE_RECOGNITION_ENABLE = b'\x0E'
    SUBSCRIBER_NUMBER_REQ    = b'\x0F'
    DTMF_TRANSMIT            = b'\x10'
    NETWORK_OPERATOR_REQ     = b'\x11'
    VOLUME_SYNC_SPEAKER      = b'\x12'
    VOLUME_SYNC_MIC          = b'\x13'
    ENHANCE_SAFETY_INDICATOR = b'\x14'
    BATTERY_LEVEL_INDICATOR  = b'\x15'
    HS_BUTTON_PRESS          = b'\x16'
    VENDOR_CMD               = b'\x17'
    TURN_OFF_ECNR            = b'\x18'

class HFP_Event_ID(enum.Enum):
    CONNECT_IND                  = b'\x00'
    CONNECT_CFM                  = b'\x01'
    CONNECT_TIMEOUT_IND          = b'\x02'
    DISCONNECT_IND               = b'\x03'
    DISCONNECT_CFM               = b'\x04'
    CALL_STATUS_IND              = b'\x05'
    CALL_SETUP_IND               = b'\x06'
    CALL_HELD_IND                = b'\x07'
    REMOTE_SUPPORT_FEATURE_IND   = b'\x08'
    GAIN_IND                     = b'\x09'
    GAIN_CFM                     = b'\x0A'
    SERVICE_IND                  = b'\x0B'
    SIGNAL_STRENGTH              = b'\x0C'
    ROAMING_STATUS               = b'\x0D'
    RING_IND                     = b'\x0E'
    BATTERY_LEVEL                = b'\x0F'
    ERROR_RESPONSE               = b'\x10'
    CALL_WAITING_ENABLE_CFM      = b'\x11'
    CALL_WAITING_IND             = b'\x12'
    CALL_HOLD_ACTION_CFM         = b'\x13'
    CALL_ANSWER_CFM              = b'\x14'
    CALL_TERMINATE_CFM           = b'\x15'
    CURRENT_CALL_IND             = b'\x16'
    CURRENT_CALL_CFM             = b'\x17'
    CALLERID_IND                 = b'\x18'
    CALLERID_ENABLE_CFM          = b'\x19'
    SUBSCRIBER_NUMBER_IND        = b'\x1A'
    SUBSCRIBER_NUMBER_CFM        = b'\x1B'
    NETWORK_OPERATOR_IND         = b'\x1C'
    NETWORK_OPERATOR_CFM         = b'\x1D'
    VOICE_RECOGNITION_ENABLE_IND = b'\x1E'
    VOICE_RECOGNITION_ENABLE_CFM = b'\x1F'
    DIAL_LAST_NUMBER_CFM         = b'\x20'
    RESPONSE_HOLD_IND            = b'\x21'
    RESPONSE_HOLD_CFM            = b'\x22'
    SMS_RCV_IND                  = b'\x23'
    HF_INDICATORS_ENABLE_IND     = b'\x24'
    HF_INDICATORS_SENT_CFM       = b'\x25'
    HS_BUTTON_PRESS_CFM          = b'\x26'
    CODEC_CONNECTION_SETUP_IND   = b'\x27'
    TURNOFF_AG_NREC_CFM          = b'\x28'
    PHONEBOOK_CFM                = b'\x29'
    END                          = b'\x2A'

class HFP_Profile(enum.Enum):
    HEADSET           = b'\x01'
    HANDSFREE         = b'\x02'
    HEADSET_HANDSFREE = b'\x03'
    TOTAL             = b'\x04'

class HFP_AtCmdStatus(enum.Enum):
    SUCCESS                    = b'\x00'
    FAIL                       = b'\x01'
    AG_FAILURE                 = b'\x02'
    # the below mean int.from_bytes(b'\x02', 'big') = AG_FAILURE.value
    NO_CONNECTION              = (int.from_bytes(b'\x02', 'big') + 1).to_bytes(1, 'big')
    OPERATION_NOT_ALLOWED      = (int.from_bytes(b'\x02', 'big') + 3).to_bytes(1, 'big')
    OPERATION_NOT_SUPPORTED    = (int.from_bytes(b'\x02', 'big') + 4).to_bytes(1, 'big')
    PH_SIM_PIN_REQUIRED        = (int.from_bytes(b'\x02', 'big') + 5).to_bytes(1, 'big')
    SIM_NOT_INSERTED           = (int.from_bytes(b'\x02', 'big') + 10).to_bytes(1, 'big')
    SIM_PIN_REQUIRED           = (int.from_bytes(b'\x02', 'big') + 11).to_bytes(1, 'big')
    SIM_PUK_REQUIRED           = (int.from_bytes(b'\x02', 'big') + 12).to_bytes(1, 'big')
    SIM_FAILURE                = (int.from_bytes(b'\x02', 'big') + 13).to_bytes(1, 'big')
    SIM_BUSY                   = (int.from_bytes(b'\x02', 'big') + 14).to_bytes(1, 'big')
    INCORRECT_PASSWORD         = (int.from_bytes(b'\x02', 'big') + 16).to_bytes(1, 'big')
    SIM_PIN2_REQUIRED          = (int.from_bytes(b'\x02', 'big') + 17).to_bytes(1, 'big')
    SIM_PUK2_REQUIRED          = (int.from_bytes(b'\x02', 'big') + 18).to_bytes(1, 'big')
    MEMORY_FULL                = (int.from_bytes(b'\x02', 'big') + 20).to_bytes(1, 'big')
    INVALID_INDEX              = (int.from_bytes(b'\x02', 'big') + 21).to_bytes(1, 'big')
    MEMORY_FAILURE             = (int.from_bytes(b'\x02', 'big') + 23).to_bytes(1, 'big')
    TEXT_STRING_TOO_LONG       = (int.from_bytes(b'\x02', 'big') + 24).to_bytes(1, 'big')
    INVALID_CHARACTERS_IN_TEXT = (int.from_bytes(b'\x02', 'big') + 25).to_bytes(1, 'big')
    DIAL_STRING_TOO_LONG       = (int.from_bytes(b'\x02', 'big') + 26).to_bytes(1, 'big')
    INVALID_CHARACTERS_IN_DAIL = (int.from_bytes(b'\x02', 'big') + 27).to_bytes(1, 'big')
    NO_NETWORK_SERVICE         = (int.from_bytes(b'\x02', 'big') + 30).to_bytes(1, 'big')
    NETWORK_TIMEOUT            = (int.from_bytes(b'\x02', 'big') + 31).to_bytes(1, 'big')
    NETWORK_NOT_ALLOWED        = (int.from_bytes(b'\x02', 'big') + 32).to_bytes(1, 'big')

class HFP_CallDirection(enum.Enum):
    OUTGOING = b'\x00'
    INCOMING = b'\x01'

class HFP_CallStatus(enum.Enum):
    NO_CALL_ACTIVE  = b'\x00'
    CALL_IS_PRESENT = b'\x01'

class HFP_CallSetupStatus(enum.Enum):
    NO_CALL_IN_PROGRESS       = b'\x00'
    INCOMING_CALL_IN_PROGRESS = b'\x01'
    OUTGOING_CALL_DIALING     = b'\x02'
    OUTGOING_CALL_ALERTING    = b'\x03'

class HFP_CallHeldStatus(enum.Enum):
    NO_CALL_HELD                = b'\x00'
    CALL_ON_HOLD_ACTIVE_SWAP    = b'\x01'
    CALL_ON_HOLD_NO_ACTIVE_CALL = b'\x02'

class HFP_CallCurrentStatus(enum.Enum):
    ACTIVE               = b'\x00'
    HELD                 = b'\x01'
    DIALING              = b'\x02'
    ALERTING             = b'\x03'
    INCOMING             = b'\x04'
    WAITING              = b'\x05'
    HELD_BY_RESPONSEHOLD = b'\x06'

class HFP_CallMode(enum.Enum):
    VOICE = b'\x00'
    DATA  = b'\x01'
    FAX   = b'\x02'

class HFP_CallMultiparty(enum.Enum):
    NO  = b'\x00'
    YES = b'\x01'

class HFP_PhoneNumberType(enum.Enum):
    UNKNOWN       = b'\x00'
    INTERNATIONAL = b'\x01'
    NATIONAL      = b'\x02'

class HFP_DialType(enum.Enum):
    SPECIFIED_NUMBER = b'\x01'
    DTMF_CODE        = b'\x02'
    DIAL_TYPE_END    = b'\x03'

class HFP_AudioTransferDirection(enum.Enum):
    AUDIO_TO_HFP = b'\x00'
    AUDIO_TO_AG  = b'\x01'
    AUDIO_TOGGLE = b'\x02'

class HFP_CallHoldActionReq(enum.Enum):
    RELEASE_HELD_REJECT_WAITING = b'\x00' # Releases all held calls
    RELEASE_ACTIVE_ACCEPT_OTHER = b'\x01' # Releases all active calls (if any exist) and accepts the other (held or waiting) call
    HOLD_ACTIVE_ACCEPT_OTHER    = b'\x02' # Places all active calls (if any exist) on hold and accepts the other
    ADD_HELD_TO_MULTIPARTY      = b'\x03' # Adds a held call to the conversation
    JOIN_CALLS_AND_HANG_UP      = b'\x04' # Connects the two calls and disconnects the subscriber from both calls

class HFP_CallHoldActionRsp(enum.Enum):
    BTRH_PUT_CALL_ON_HOLD = b'\x00'
    BTRH_ACCEPT_HELD_CALL = b'\x01'
    BTRH_REJECT_HELD_CALL = b'\x02'
# endregion

# region RTU
class RTU_CMD_ID(enum.Enum):
    READ_ALL_PAIRED_DEVICE      = b'\x00'
    ERASE_ALL_PAIRED_DEVICE     = b'\x01'
    DEL_SPECIFIED_PAIRED_DEVICE = b'\x02'
    LOAD                        = b'\x03'
    SAVE                        = b'\x04'
    DUMP_BLOCK                  = b'\x05'
    DUMP_RTU                    = b'\x06'
    ERASE_SECTOR                = b'\x07'
    READ_SPECIFIC_PAIRED_DEVICE = b'\x08'
# endregion

# region DFU
class DFU_CMD_ID(enum.Enum):
    START         = b'\x00'
    INIT          = b'\x01'
    UPDATE        = b'\x02'
    VALID         = b'\x03'
    END           = b'\x04'
    RESET         = b'\x05'
    DBG_DUMP      = b'\x06'
    DBG_WRITE_HDR = b'\x07'
# endregion

# region AVDTP
class AVDTP_CMD_ID(enum.Enum):
    CONNECT_REQ            = b'\x00'
    DISCONNECT_REQ         = b'\x01'
    DISCOVER_REQ           = b'\x02'
    GETCAPABILITIES_REQ    = b'\x03'
    GETALLCAPABILITIES_REQ = b'\x04'
    SETCONFIGURATION_REQ   = b'\x05'
    GETCONFIGURATION_REQ   = b'\x06'
    OPEN_REQ               = b'\x07'
    CLOSE_REQ              = b'\x08'
    START_REQ              = b'\x09'
    SUSPEND_REQ            = b'\x0A'
    RECONFIGURATION_REQ    = b'\x0B'
    SECURITYCONTROL_REQ    = b'\x0C'
    ABORT_REQ              = b'\x0D'
    DELAYREPORT_REQ        = b'\x0E'
    SEND_MEDIA_PACKET      = b'\x0F'
    STOP_MEDIA_PACKET      = b'\x10'
    REGISTER_CALLBACK      = b'\x80'

class AVDTP_Event_ID(enum.Enum):
    CONNECT_REQ_IND          = b'\x01'
    CONNECT_COMPLETE_CFM     = b'\x02'
    CONNECT_TIMEOUT_IND      = b'\x03'
    DISCONNECT_REQ_IND       = b'\x04'
    DISCONNECT_REQ_CFM       = b'\x05'
    DISCOVER_IND             = b'\x06'
    DISCOVER_CFM             = b'\x07'
    GET_CAPABILITIES_IND     = b'\x08'
    GET_CAPABILITIES_CFM     = b'\x09'
    SET_CONFIGURATION_IND    = b'\x0A'
    SET_CONFIGURATION_CFM    = b'\x0B'
    GET_CONFIGURATION_IND    = b'\x0C'
    GET_CONFIGURATION_CFM    = b'\x0D'
    OPEN_IND                 = b'\x0E'
    OPEN_CFM                 = b'\x0F'
    CLOSE_IND                = b'\x10'
    CLOSE_CFM                = b'\x11'
    START_IND                = b'\x12'
    START_CFM                = b'\x13'
    SUSPEND_IND              = b'\x14'
    SUSPEND_CFM              = b'\x15'
    RECONFIGURE_IND          = b'\x16'
    RECONFIGURE_CFM          = b'\x17'
    SECURITY_CONTROL_IND     = b'\x18'
    SECURITY_CONTROL_CFM     = b'\x19'
    ABORT_IND                = b'\x1A'
    ABORT_CFM                = b'\x1B'
    GET_ALL_CAPABILITIES_IND = b'\x1C'
    GET_ALL_CAPABILITIES_CFM = b'\x1D'
    DELAY_REPORT_IND         = b'\x1E'
    DELAY_REPORT_CFM         = b'\x1F'
    RESPONSE_TIMEOUT         = b'\x40'
# endregion

# region AVCTP
class AVCTP_CMD_ID(enum.Enum):
    CONNECT_REQ                   = b'\x00'
    CONNECT_RSP                   = b'\x01'
    DISCONNECT_REQ                = b'\x02'
    SEND_SINGLE_COMMAND_MESSAGE   = b'\x03'
    SEND_FRAGMENT_COMMAND_MESSAGE = b'\x04'
    SEND_SINGLE_RESPONSE_MESSAGE  = b'\x05'
    REGISTER_CALLBACK             = b'\x80'
    # BROWSING_CONNECT_REQ          = b'\xA0'

class AVCTP_Event_ID(enum.Enum):
    CONNECT_REQ_IND      = b'\x01'
    CONNECT_COMPLETE_CFM = b'\x02'
    CONNECT_TIMEOUT_IND  = b'\x03'
    DISCONNECT_IND       = b'\x04'
    DISCONNECT_CFM       = b'\x05'
    MESSAGE_REC_IND      = b'\x06'
# endregion

# region AVRCP
class AVRCP_CMD_ID(enum.Enum):
    REGISTER_NOTIFICATION       = b'\x00'
    GET_CAPABILITY              = b'\x01'
    LIST_ATTRS                  = b'\x02'
    LIST_VALUES                 = b'\x03'
    GET_CURRENT_VALUE           = b'\x04'
    SET_VALUE                   = b'\x05'
    GET_ATTR_TEXT               = b'\x06'
    GET_VALUE_TEXT              = b'\x07'
    INFORM_DISPLAYABLE_CHAR_SET = b'\x08'
    INFO_BAT_STATUS             = b'\x09'
    GET_ELEMENT_ATTRS           = b'\x0A'
    PLAY_STATUS                 = b'\x0B'
    REQUEST_CONT_RSP            = b'\x0C'
    ABOUT_CONT_RSP              = b'\x0D'
    SET_ABSOLUTE_VOLUME         = b'\x0E'
    SET_ADDRESSED_PLAYER        = b'\x0F'
    PLAY_ITEM                   = b'\x10'
    ADD_TO_NOW_PLAYING          = b'\x11'
    PASSTHROUTH_REQ             = b'\x12'
    REG_NOTIFICATION_RSP        = b'\x13'
    SET_ABSOLUTE_VOLUME_RSP     = b'\x14'
    REG_NOTIFICATION_CHANGED    = b'\x15'
    GET_FOLDER_ITEM             = b'\x16'
    GET_TOTAL_NUM_OF_ITEM       = b'\x17'
    SET_BROWSED_PLAYER          = b'\x18'
    CHANGE_PATH                 = b'\x19'
    GET_ITEM_ATTRS              = b'\x1A'
    SEARCH                      = b'\x1B'
    CONNECT_REQ                 = b'\x1C'
    DISCONNECT_REQ              = b'\x1D'
    UNIT_SUBUNIT_INFO_RSP       = b'\x1E'
    EVENT_REGISTERATION         = b'\x1F'

class AVRCP_Event_ID(enum.Enum):
    CONNECT_IND                  = b'\x00'
    CONNECT_CFM                  = b'\x01'
    CONNECT_TIMEOUT_NOTI         = b'\x02'
    DISCONNECT_NOTI              = b'\x03'
    DISCONNECT_CFM               = b'\x04'
    REGISTER_NOTIFICATION_RSP    = b'\x05'
    GET_CAPABILITIES             = b'\x06'
    LIST_PLAYER_APP_SET_ATTR     = b'\x07'
    LIST_PLAYER_APP_SET_VAL      = b'\x08'
    GET_CURR_PLAYER_APP_SET_VAL  = b'\x09'
    SET_PLAYER_APP_SET_VAL       = b'\x0A'
    GET_PLAYER_APP_SET_ATTR_TEXT = b'\x0B'
    GET_PLAYER_APP_SET_VAL_TEXT  = b'\x0C'
    INFORM_DISPLAYABLE_CHAR_SET  = b'\x0D'
    INFORM_BATTERY_STATUS_OFCT   = b'\x0E'
    GET_ELEMENT_ATTR             = b'\x0F'
    GET_PLAY_STATUS		         = b'\x10'
    REQ_CONTINUE_RSP             = b'\x11'
    ABORT_CONTINUE_RSP           = b'\x12'
    SET_ABS_VOLUME_RSP           = b'\x13'
    SET_ADDRESSED_PLAYER         = b'\x14'
    PLAY_ITEM                    = b'\x15'
    ADD_TO_NOW_PLAYING           = b'\x16'
    TRACK_CHANGED                = b'\x17'
    PLAYBACK_STATUS_CHANGED      = b'\x18'
    TRACK_REACHED_END            = b'\x19'
    TRACK_REACHED_START          = b'\x1A'
    PLAYBACK_POS_CHANGED         = b'\x1B'
    BATT_STATUS_CHANGED          = b'\x1C'
    SYSTEM_STATUS_CHANGED        = b'\x1D'
    PLAYER_APP_SETTING_CHANGED   = b'\x1E'
    NOW_PLAYING_CONTENT_CHANGED  = b'\x1F'
    AVAILABLE_PLAYERS_CHANGED    = b'\x20'
    ADDRESSED_PLAYER_CHANGED     = b'\x21'
    UIDS_CHANGED                 = b'\x22'
    VOLUME_CHANGED               = b'\x23'
    PASSTHROUGH_REQ              = b'\x24'
    PASSTHROUGH_RSP              = b'\x25'
    REGISTER_NOTIFICATION_REQ    = b'\x26'
    SET_ABS_VOLUME_REQ	         = b'\x27'
    UNIT_SUBUNIT_INFO_REQ        = b'\x28'
    GET_FOLDER_ITEMS_RSP         = b'\x29'
    GET_TOTAL_NUM_OF_ITEMS_RSP   = b'\x2A'
    SET_BROWSERED_PLAYER_RSP     = b'\x2B'
    CHANGE_PATH_RSP              = b'\x2C'
    GET_ITEM_ATTRS_RSP           = b'\x2D'
    SEARCH_RSP                   = b'\x2E'
    GENERAL_REJECT               = b'\x2F'

class AVRCP_ELEMENT_ID(enum.Enum):
    PLAYING = b'\x00'

class AVRCP_PDU_ID(enum.Enum):
    GET_CAPABILITY                    = b'\x10'
    LIST_PLAYER_APP_SETTING_ATTR      = b'\x11'
    LIST_PLAYER_APP_SETTING_VALUE     = b'\x12'
    GET_CURR_PLAYER_APP_SETTING_VALUE = b'\x13'
    SET_PLAYER_APP_SETTING_VALUE      = b'\x14'
    GET_PLAYER_APP_SETTING_ATTR_TEXT  = b'\x15'
    GET_PLAYER_APP_SETTING_VALUE_TEXT = b'\x16'
    INFORM_DISPLAYABLE_CHAR_SET       = b'\x17'
    INFORM_BATTERY_STATUS_OFCT        = b'\x18'
    GET_ELEMENT_ATTRIBUTE             = b'\x20'
    GET_PLAY_STATUS                   = b'\x30'
    REGISTER_NOTIFICATION             = b'\x31'
    REQ_CONTINUING_RESP               = b'\x40'
    ABORT_CONTINUING_RESP             = b'\x41'
    SET_ABSOLUTE_VOLUME               = b'\x50'
    SET_ADDRESSED_PLAYER              = b'\x60'
    PLAY_ITEM                         = b'\x74'
    ADD_TO_NOW_PLAYING                = b'\x90'
    GET_FOLDER_ITEMS                  = b'\x71'
    GET_TOTAL_NUM_OF_ITEMS            = b'\x75'
    SET_BROWSERED_PLAYER              = b'\x70'
    CHANGE_PATH                       = b'\x72'
    GET_ITEM_ATTRS                    = b'\x73'
    SEARCH                            = b'\x80'
    GENERAL_REJECT                    = b'\xA0'

class AVRCP_RESPONSE(enum.Enum):
    NOT_IMPLEMENT = b'\x08'
    ACCEPT        = b'\x09'
    REJECT        = b'\x0A'
    STABLE        = b'\x0C'
    CHANGED       = b'\x0D'
    INTERIM       = b'\x0F'

class AVRCP_CAPABILITY_OPTION(enum.Enum):
    COMPAYN_ID       = b'\x02'
    EVENTS_SUPPORTED = b'\x03'

class AVRCP_BUTTON_STATUS(enum.Enum):
    PRESSED  = b'\x00'
    RELEASED = b'\x01'

class AVRCP_OPID(enum.Enum):
    SELECT 	   	  	 	= b'\x00'
    UP 	   	   	  	 	= b'\x01'
    DOWN   	   	  	 	= b'\x02'
    LEFT   	   	  	 	= b'\x03'
    RIGHT  	   	  	 	= b'\x04'
    RIGHT_UP   	  	 	= b'\x05'
    RIGHT_DOWN 	  	 	= b'\x06'
    LEFT_UP    	  	 	= b'\x07'
    LEFT_DOWN  	  	 	= b'\x08'
    ROOT_MENU  	  	 	= b'\x09'
    SETUP_MENU 	  	 	= b'\x0A'
    CONTENTS_MENU 	 	= b'\x0B'
    FAVORITE_MENU 	 	= b'\x0C'
    EXIT          	 	= b'\x0D'
    B0			  	 	= b'\x20'
    B1 			  	 	= b'\x21'
    B2 			  	 	= b'\x22'
    B3 			  	 	= b'\x23'
    B4 			  	 	= b'\x24'
    B5 			  	 	= b'\x25'
    B6 			  	 	= b'\x26'
    B7 			  	 	= b'\x27'
    B8 			  	 	= b'\x28'
    B9 			  	 	= b'\x29'
    DOT 		  	 	= b'\x2A'
    ENTER 		  	 	= b'\x2B'
    CLEAR 		  	 	= b'\x2C'
    CHANNEL_UP    	 	= b'\x30'
    CHANNEL_DOWN  	 	= b'\x31'
    PREVIOUS_CHANNEL 	= b'\x32'
    SOUND_SELECT	 	= b'\x33'
    INPUT_SELECT        = b'\x34'
    DISPLAY_INFORMATION = b'\x35'
    HELP 				= b'\x36'
    PAGE_UP 			= b'\x37'
    PAGE_DOWN   		= b'\x38'
    POWER				= b'\x40'
    VOLUME_UP   		= b'\x41'
    VOLUME_DOWN         = b'\x42'
    MUTE 				= b'\x43'
    PLAY 				= b'\x44'
    STOP 				= b'\x45'
    PAUSE               = b'\x46'
    RECORD 				= b'\x47'
    REWIND 				= b'\x48'
    FAST_FORWARD		= b'\x49'
    EJECT				= b'\x4A'
    FORWARD 			= b'\x4B'
    BACKWARD			= b'\x4C'
    ANGLE				= b'\x50'
    SUBPICTURE 			= b'\x51'
    F1					= b'\x70'
    F2 					= b'\x71'
    F3 					= b'\x72'
    F4 					= b'\x73'
    F5 					= b'\x74'
    VENDOR_UNIQUE		= b'\x7E'

class AVRCP_UNIT_INFO_OPCODE(enum.Enum):
    UNIT_INFO     =	b'\x30'
    SUB_UNIT_INFO =	b'\x31'

class AVRCP_SUPP_ID(enum.Enum):
    PLAYBACK_STATUS_CHANGED   = b'\x01'
    TRACK_CHANGED             = b'\x02'
    TRACK_REACHED_END         = b'\x03'
    TRACK_REACHED_START       = b'\x04'
    PLAYBACK_POS_CHANGED      = b'\x05'
    BATT_STATUS_CHANGED       = b'\x06'
    SYSTEM_STATUS_CHANGED     = b'\x07'
    PLAYER_SETTING_CHANGED    = b'\x08'
    NOW_PLAYING_CHANGED       = b'\x09'
    AVAILABLE_PLAYERS_CHANGED = b'\x0A'
    ADDRESSED_PLAYER_CHANGED  = b'\x0B'
    UIDS_CHANGED              = b'\x0C'
    VOLUME_CHANGED            = b'\x0D'

class AVRCP_MEDIA_ATTR_ID(enum.Enum):
    TITLE               = b'\x00\x00\x00\x01'
    ARTIST_NAME         = b'\x00\x00\x00\x02'
    ALBUM_NAME          = b'\x00\x00\x00\x03'
    TRACK_NUM           = b'\x00\x00\x00\x04'
    TOTAL_NUM_OF_TRACKS = b'\x00\x00\x00\x05'
    GENRE               = b'\x00\x00\x00\x06'
    PLAYING_TIME        = b'\x00\x00\x00\x07'

class AVRCP_EQUALIZER_STATUS(enum.Enum):
    OFF = b'\x01'
    ON  = b'\x02'

class AVRCP_REPEAT_MODE_STATUS(enum.Enum):
    OFF                 = b'\x01'
    SIGNAL_TRACK_REPEAT = b'\x02'
    ALL_TRACK_REPEAT    = b'\x03'
    GROUP_REPEAT        = b'\x04'

class AVRCP_SHUFFLE_STATUS(enum.Enum):
    OFF               = b'\x01'
    ALL_TRACK_SHUFFLE = b'\x02'
    GROUP_SHUFFLE     = b'\x03'

class AVRCP_SCAN_STATUS(enum.Enum):
    OFF            = b'\x01'
    ALL_TRACK_SCAN = b'\x02'
    GROUP_SCAN     = b'\x03'

class AVRCP_PLAYER_APP_ATTR_ID(enum.Enum):
    EQUALIZER   = b'\x01'
    REPEAT_MODE = b'\x02'
    SHUFFLE     = b'\x03'
    SCAN        = b'\x04'

class AVRCP_SCOPE_MEDIA_PLAYER(enum.Enum):
    LIST               = b'\x00'
    VIRTUAL_FILESYSTEM = b'\x01'
    SEARCH             = b'\x02'
    NOW_PLAYING        = b'\x03'

class AVRCP_CHANNEL_TYPE(enum.Enum):
    CONTROL  = b'\x00'
    BROWSING = b'\x01'

class AVRCP_DIRECTION_FOLDER(enum.Enum):
    UP   = b'\x00'
    DOWN = b'\x01'
# endregion

# region BT L2CAP
class BT_L2CAP_CMD_ID(enum.Enum):
    OPEN_CHAN_REQ = b'\x01'
    DISCONNECT    = b'\x02'
    REGISTER_PSM  = b'\x03'
    OPEN_CHAN_RSP = b'\x04'
    SEND_DATA     = b'\x05'
    INFO_REQ      = b'\x06'
    ECHO_REQ      = b'\x07'
    ERM_SET_CHANNEL_STATUS = b'\x0C'

class BT_L2CAP_Event_ID(enum.Enum):
    OPEN_CHANNEL_IND      = b'\x00'
    OPEN_CHANNEL_COMPLETE = b'\x01'
    DISCONNECT_IND        = b'\x02'
    DISCONNECT_CFM        = b'\x03'
    RCV_DATA_IND          = b'\x04'
    TRANSACTION_TIMEOUT   = b'\x05'
    INFORMATION_RSP       = b'\x06'
    ECHO_RSP              = b'\x07'

class BT_L2CAP_CONF_OPTIONS(enum.Enum):
    MTU = b'\x01'
    FT  = b'\x02'
    QOS = b'\x03'
    RFC = b'\x04'
    FCS = b'\x05'
    EFS = b'\x06'
    EWS = b'\x07'

class BT_L2CAP_CONN_RSP_RESULT(enum.Enum):
    SUCCESSFUL   = b'\x00\x00'
    PENDING      = b'\x00\x01'
    REFUSED_PNS  = b'\x00\x02'
    REFUSED_SB   = b'\x00\x03'
    REFUSED_NRA  = b'\x00\x04'
    REFUSED_ISC  = b'\x00\x06'
    REFUSED_SCAA = b'\x00\x07'

class BT_L2CAP_CONN_RSP_STATUS(enum.Enum):
    NO_FURTHER_INFORMATION = b'\x00\x00'
    AUTHENTICATION_PENDING = b'\x00\x01'
    AUTHORIZATION_PENDING  = b'\x00\x02'

class BT_L2CAP_INFO_TYPE(enum.Enum):
    CONECTIONLESS_MTU = b'\x00\x01'
    EXTENDED_FEATURES = b'\x00\x02'
    FIX_CHANNELS      = b'\x00\x03'

class BT_L2CAP_CMD_REJECT_REASON(enum.Enum):
    NOT_UNDERSTOOD = b'\x00\x00'
    MTU_EXCEEDED   = b'\x00\x01'
    INVALID_CID    = b'\x00\x02'
# endregion

# region A2DP
class A2DP_CMD_ID(enum.Enum):
    SIGNAL_CONNECT_REQ = b'\x00'
    STREAM_CONNECT_REQ = b'\x01'

class A2DP_Event_ID(enum.Enum):
    CONNECT_IND 			= b'\x01'
    CONNECT_CFM             = b'\x02'
    DISCONNECT_IND          = b'\x03'
    DISCONNECT_CFM          = b'\x04'
    CONNECT_TIMEOUT_IND     = b'\x05'
    GET_CAPABILITIES_CFM    = b'\x06'
    SET_CONFIGURATION_IND   = b'\x07'
    SET_CONFIGURATION_CFM   = b'\x08'
    GET_CONFIGURATION_CFM   = b'\x09'
    RECONFIGURE_IND         = b'\x0A'
    RECONFIGURE_CFM         = b'\x0B'
    OPEN_IND                = b'\x0C'
    OPEN_CFM                = b'\x0D'
    START_IND               = b'\x0E'
    START_CFM               = b'\x0F'
    CLOSE_IND               = b'\x10'
    CLOSE_CFM               = b'\x11'
    SUSPEND_IND             = b'\x12'
    SUSPEND_CFM             = b'\x13'
    ABORT_IND               = b'\x14'
    ABORT_CFM               = b'\x15'
    SECURITY_CONTROL_IND    = b'\x16'
    SECURITY_CONTROL_CFM    = b'\x17'
    DELAY_REPORT_IND        = b'\x18'
    DELAY_REPORT_CFM        = b'\x19'
    DISCOVER_CFM            = b'\x1A'
    RESPONSE_TIMEOUT 		= b'\x40'
# endregion

# region BLE L2CAP
class BLE_L2CAP_CMD_ID(enum.Enum):
    BLE_CPU          = b'\x00'
    CB_CONN_REQ      = b'\x01'
    CB_ADD_CREDIT    = b'\x02'
    CB_SEND_SDU      = b'\x03'
    CB_DISCONNECT    = b'\x04'
    CB_CONN_RSP      = b'\x05'
    SPSM_REGISTER    = b'\x06'
    ECB_CONN_REQ     = b'\x07'
    ECB_CONN_RSP     = b'\x08'
    ECB_RECONFIG_REQ = b'\x09'

class BLE_L2CAP_Event_ID(enum.Enum):
    CONN_PARA_UPDATE_REQ = b'\x00'
    CONN_PARA_UPDATE_RSP = b'\x01'
    CMD_REJECT_RSP		 = b'\x02'
    CB_CHANNEL_OPEN_REQ  = b'\x03'
    CB_CHANNEL_OPEN_CFM  = b'\x04'
    CB_SDU_IND		 	 = b'\x05'
    CB_ADD_CREDITS_IND   = b'\x06'
    CB_DISC_IND			 = b'\x07'
    CB_DISC_CFM			 = b'\x08'
    ECB_CHANNEL_OPEN_REQ = b'\x09'
    ECB_CHANNEL_OPEN_CFM = b'\x0A'
    ECB_RECONFIG_IND     = b'\x0B'
    ECB_RECONFIG_CFM     = b'\x0C'

class BLE_L2CAP_SPSM(enum.Enum):
    DYNAMIC_MIN     = b'\x00\x80'
    DYNAMIC_MAX     = b'\x00\xFF'
    MAX_PDU_SIZE    = 251
    MAX_SPSM_NUM    = 1
    MAX_CB_NUM      = b'\x05'
    PERMISSION_AUTH = b'\x01'
    PERMISSION_ENC  = b'\x02'

# endregion

# region PTS TEST
class PTS_TEST_Event_ID(enum.Enum):
    GATTS_WRITE        = b'\x00'
    GATTS_CONFIRMATION = b'\x01'
    GATTS_UPDATEMTU    = b'\x02'

class PTS_TEST_HDL(enum.Enum):
    PRIMSVC          = b'\x00\x50'
    CHAR_CHAR1       = b'\x00\x51'
    CHARVAL_CHAR1    = b'\x00\x52'
    CHAR1_CCCD       = b'\x00\x53'
    CHAR_CHAR2       = b'\x00\x54'
    CHARVAL_CHAR2    = b'\x00\x55'
    CHAR2_USERDESC   = b'\x00\x56'
    CHAR_CHAR3       = b'\x00\x57'
    CHARVAL_CHAR3    = b'\x00\x58'
    CHAR_CHAR4       = b'\x00\x59'
    CHARVAL_CHAR4    = b'\x00\x5A'
    CHAR_CHAR5       = b'\x00\x5B'
    CHARVAL_CHAR5    = b'\x00\x5C'
    CHAR_CHAR6       = b'\x00\x5D'
    CHARVAL_CHAR6    = b'\x00\x5E'
    CHAR_CHAR7       = b'\x00\x5F'
    CHARVAL_CHAR7    = b'\x00\x60'
    INCLUDEVAL_CHAR1 = b'\x00\x61'
    APP_PTS_TTL_ATT  = b'\x12'
    PTS_START_HDL    = b'\x00\x50'
    PTS_END_HDL      = b'\x00\x61'
# endregion

# region PERIPHERAL
class I2C_CMD_ID(enum.Enum):
    CONFIG     = b'\x00'
    READ       = b'\x01'
    WRITE      = b'\x02'
    COMBINE_WR = b'\x03'

class LED_CMD_ID(enum.Enum):
    INIT        = b'\x00'
    CLOSE       = b'\x01'
    SINGLEFLASH = b'\x02'
    COMBOFLASH  = b'\x03'
    INTENSITY   = b'\x04'
    END         = b'\x05'

class SQIFLASH_CMD_ID(enum.Enum):
    READ  = b'\x00'
    WRITE = b'\x01'
    ERASE = b'\x02'

class IAP2_Event_ID(enum.Enum):
    CONNECTED_IND       = b'\x00'
    CONNECTED_CFM       = b'\x01'
    EA_SESSION_OPEN     = b'\x02'
    CONNECT_TIMEOUT_IND = b'\x03'
    DISCONNECTED_IND    = b'\x04'
    DISCONNECTED_CFM    = b'\x05'
    RCV_DATA            = b'\x06'
    RCV_CREDIT          = b'\x07'
# endregion

# region SDP
class SDP_CMD_ID(enum.Enum):
    CLIENT_REGISTER_CALLBACK            = b'\x00'
    CLIENT_SERVICE_SEARCH_REQ           = b'\x01'
    CLIENT_SERVICE_ATTRIBUTE_REQ        = b'\x02'
    CLIENT_SERVICE_ATTRIBUTE_SEARCH_REQ = b'\x03'

class SDP_Event_ID(enum.Enum):
    SVC_SEARCH_RESP      = b'\x00'
    SVC_ATTR_RESP        = b'\x01'
    SVC_SEARCH_ATTR_RESP = b'\x02'
    TRANSACTION_TIMEOUT  = b'\x03'
    DISC                 = b'\x04'

class SDP_Parser_Event_ID(enum.Enum):
    RFCOMM_SVC_CHAN_RESP = b'\x00'
    L2CAP_PSM            = b'\x01'
    PROFILE_VERSION      = b'\x02'
    CONNECT_TIMEOUT      = b'\x03'
    DISCONNECT           = b'\x04'
# endregion

# region RFCOMM
class RFCOMM_CMD_ID(enum.Enum):
    CONSTRUCT_SESSION        = b'\x00'
    INITIATE_SESSION		 = b'\x01'
    RESPOND_INITIATE_SESSION = b'\x02'
    SEND_DISC_DLC  		     = b'\x03'
    SEND_UIH_DATA            = b'\x04'
    SEND_CREDIT              = b'\x05'
    SEND_RLS                 = b'\x06'

class RFCOMM_Event_ID(enum.Enum):
    OPEN_SESSION_IND    = b'\x00'
    OPEN_SESSION_CFM    = b'\x01'
    DISCONNECT_IND      = b'\x02'
    DISCONNECT_CFM      = b'\x03'
    CONNECT_TIMEOUT_IND = b'\x04'
    RCV_DATA_IND        = b'\x05'
    RCV_CREDIT_IND      = b'\x06'

class RFCOMM_ROLE(enum.Enum):
    RESPONDER = b'\x00'
    INITIATOR = b'\x01'

class RFCOMM_RLS_STATUS(enum.Enum):
    NO_ERROR      = b'\x00'
    OVERRUN_ERROR = b'\x03'
    PARITY_ERROR  = b'\x05'
    FRAMING_ERROR = b'\x09'
# endregion

# region SPP
class SPP_CMD_ID(enum.Enum):
    INITIATOR_CONNECT_REQ = b'\x00'

class SPP_Event_ID(enum.Enum):
    CONNECTED_IND       = b'\x00'
    CONNECTED_CFM       = b'\x01'
    CONNECT_TIMEOUT_IND = b'\x02'
    DISCONNECTED_IND    = b'\x03'
    DISCONNECTED_CFM    = b'\x04'
    RCV_DATA            = b'\x05'
    RCV_CREDIT          = b'\x06'
# endregion

# region PBAP/GOEP
class PBAP_CMD_ID(enum.Enum):
    CONNECT            = b'\x00'
    PULL_PHONEBOOK     = b'\x01'
    SET_PHONEBOOK      = b'\x02'
    PULL_VCARD_LISTING = b'\x03'
    PULL_VCARD_ENTRY   = b'\x04'
    DISCONNECT         = b'\x05'
    ABORT              = b'\x06'
    APP_PARAMS_CONFIG  = b'\x07'
    CONTINUE           = b'\xA0'

class PBAP_Event_ID(enum.Enum):
    CONNECT_CFM            = b'\x00'
    DISCONNECT_IND         = b'\x01'
    DISCONNECT_CFM         = b'\x02'
    RCV_ERROR_RSP          = b'\x03'
    PULL_PHONEBOOK_CFM     = b'\x04'
    SET_PHONEBOOK_CFM      = b'\x05'
    PULL_VCARD_LISTING_CFM = b'\x06'
    PULL_VCARD_ENTRY_CFM   = b'\x07'
    ABORT_CFM              = b'\x08'
    SUPPORTED_FEATURES     = b'\x09'

class PBAP_APP_CONFIG_ID(enum.Enum):
    CONFIG_RESET                   = b'\x00'
    CONFIG_ORDER                   = b'\x01'
    CONFIG_SEARCH_VALUE            = b'\x02'
    CONFIG_SEARCH_PROPERTY         = b'\x03'
    CONFIG_MAX_LIST_COUNT          = b'\x04'
    CONFIG_LIST_START_OFFSET       = b'\x05'
    CONFIG_PROPERTY_SELECTOR       = b'\x06'
    CONFIG_FORMAT                  = b'\x07'
    CONFIG_PHONE_BOOK_SIZE         = b'\x08'
    CONFIG_VCARD_SELECTOR          = b'\x09'
    CONFIG_VCARD_SELECTOR_OPERATOR = b'\x0A'
    CONFIG_RST_NEW_MISSED_CALLS    = b'\x0B'

class PBAP_ObjectType(enum.Enum):
    PB  = b'\x00'
    ICH = b'\x01'
    OCH = b'\x02'
    MCH = b'\x03'
    CCH = b'\x04'
    SPD = b'\x05'
    FAV = b'\x06'

class PBAP_PhoneBookAction(enum.Enum):
    GO_BACK_TO_ROOT = b'\x00'
    GO_DOWN_1_ELVEL = b'\x01'
    GO_UP_1_ELVEL   = b'\x02'

class PBAP_PhoneBookFolder(enum.Enum):
    TELECOM	= b'\x00'
    SIM1   	= b'\x01'
    PB     	= b'\x02'
    ICH    	= b'\x03'
    OCH    	= b'\x04'
    MCH    	= b'\x05'
    CCH    	= b'\x06'
    SPD     = b'\x07'
    FAV     = b'\x08'
    NULL    = b'\x09'

class PBAP_NAME_OPT(enum.Enum):
    VCF      = b'\x00'
    X_BT_UID = b'\x01'

class PBAP_STATUS(enum.Enum):
    SUCCESS 			       = b'\x00'
    FAILURE 			       = b'\x01'
    ABORTED 			       = b'\x02'
    PENDING 			       = b'\x03'
    NOT_IDLE 			       = b'\x04'
    WRONG_STATE 		       = b'\x05'
    SDP_FAILURE_RESOURCE       = b'\x06'
    SDP_FAILURE_BLUESTACK      = b'\x07'
    REMOTE_DISCONNECT 	       = b'\x08'
    SDP_UNAUTHORISED           = b'\x10'
    SDP_NO_REPOSITORY	       = b'\x11'
    SDP_NOT_FOUND		       = b'\x12'
    VCL_NO_PARAM_RESOURCES     = b'\x20'
    VCL_NO_PHONEBOOK_FOLDER    = b'\x21'
    VCL_INVALID_PHONEBOOK      = b'\x22'
    VCE_NO_PARAM_RESOURCES     = b'\x30'
    VCE_NO_NAME_RESOURCES      = b'\x31'
    VCE_INVALID_ENTRY		   = b'\x32'
    PPB_NO_PARAM_RESOURCES     = b'\x40'
    PPB_NO_NAME_RESOURCES      = b'\x41'
    PPB_NO_REQUIRED_NAME       = b'\x42'
    PPB_NO_REPOSITORY          = b'\x43'
    PROP_SDP_ERROR             = b'\x44'
    CONNECT_REJECT_KEY_MISSING = b'\x45'

class GOEP_Event_ID(enum.Enum):
    OBEX_CONNECT_IND        = b'\x00'
    OBEX_CONNECT_CFM        = b'\x01'
    OBEX_DISCONNECT_IND     = b'\x02'
    OBEX_DISCONNECT_CFM     = b'\x03'
    OBEX_CONNECT_TIMEOUT    = b'\x04'
    OBEX_RCV_PUT_REQ        = b'\x05'
    OBEX_RCV_GET_REQ        = b'\x06'
    OBEX_RCV_ABORT_REQ      = b'\x07'
    OBEX_RCV_SETPATH_REQ    = b'\x08'
    OBEX_RCV_CONTINUE_RSP   = b'\x09'
    OBEX_RCV_SUCCESSFUL_RSP = b'\x0A'
    OBEX_RCV_ERROR_RSP      = b'\x0B'
    OBEX_RCV_UNEXPECTED     = b'\x0C'
    OBEX_RCV_INVALID        = b'\x0D'
# endregion

# region CFPS/CSB
class GFPS_CMD_ID(enum.Enum):
    ADV_DISCOVERABLE    = b'\x00'
    ADV_NONDISCOVERABLE = b'\x01'

class CSB_Event_ID(enum.Enum):
    DISCONNECTION_COMPLETE = b'\x00'
    CONNECTION_COMPLETE    = b'\x01'
    COMMAND_RCV_REPORT     = b'\x02'
    ACTION_IND             = b'\x03'
    LINK_STATUS_REPORT     = b'\x04'
    VENDOR_EVENT           = b'\x05'
    SYNC_STATUS            = b'\x06'
    EXCHANGE_DATA          = b'\x07'
# endregion

# region UTILITY
class UTILITY_CMD_ID(enum.Enum):
    SHUTDOWN         = b'\x00'
    CURR_CONN_HANDLE = b'\x01'
    INIT_DONE        = b'\x02'

class UTILITY_Event_ID(enum.Enum):
    PAIRED_RECORD_FULL = b'\x00'
    PAIRED_KEY_NOTIFY  = b'\x01'
    REMOTE_BOND_LOST   = b'\x02'

class MBA_RES(enum.Enum):
    SUCCESS                 = b'\x00\x00'
    FAIL                    = b'\x00\x01'
    OOM                     = b'\x00\x02'
    INVALID_PARA            = b'\x00\x03'
    NO_RESOURCE             = b'\x00\x04'
    BAD_STATE               = b'\x00\x05'
    PENDING_DUE_TO_SECURITY = b'\x00\x06'
    DEVICE_BUSY             = b'\x00\x07'
    ATT_BASE                = b'\x01\x00'
    PERIPHERAL_BASE         = b'\x08\x00'
# endregion
