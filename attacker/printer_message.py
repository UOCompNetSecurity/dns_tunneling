from dataclasses import dataclass
from enum import Enum

class PrinterMessageType(Enum): 
    ERROR = 1,
    SENT = 2,
    RECEIVED = 3
    PROBE = 4,
    FILE_START = 5,
    FILE_END = 6

@dataclass 
class PrinterMessage: 
    message: str 
    message_type: PrinterMessageType
    





        
