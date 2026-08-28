from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from collections.abc import Callable

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .tend_cxs import ConnectionInfo, TendCamera

_LOGGER = logging.getLogger(__name__)

MAGIC = b"SDNK"
VERSION = bytes((1, 0, 0))
TYPE_REGISTER = 1
TYPE_PEERS = 2
TYPE_PUNCH = 3
TYPE_CONNECT = 4
TYPE_CONNECTED = 5
TYPE_RELAY_ACK = 100

RecordCallback = Callable[[bytes], None]


def _sdnk(packet_type: int, payload: bytes) -> bytes:
    header = bytearray(20)
    header[:4] = MAGIC
    header[4:7] = VERSION
    header[7] = packet_type
    struct.pack_into(">I", header, 16, len(payload))
    return bytes(header) + payload


def _media_id(kind: str, device_id: str) -> bytes:
    value = f"{kind}_{device_id}".encode("ascii", errors="ignore")[:32]
    return value + bytes(32 - len(value))


def _register_packet(
    kind: str,
    device_id: str,
    local_ip: str,
    local_port: int,
    control: bool,
) -> bytes:
    ident = _media_id(kind, device_id)
    address = bytes(int(part) for part in local_ip.split("."))
    port = struct.pack(">H", local_port)
    payload = (
        bytes((1, 0, 0, int(control)))
        + kind.encode("ascii")
        + address
        + bytes(16)
        + port
        + ident
        + ident
    )
    return _sdnk(TYPE_REGISTER, payload)


def _relay_ack_packet(kind: str, device_id: str, control: bool) -> bytes:
    ident = _media_id(kind, device_id)
    return _sdnk(
        TYPE_RELAY_ACK,
        bytes((1, int(control))) + kind.encode("ascii") + ident + ident,
    )


def _punch_packet(kind: str, device_id: str, sequence: int) -> bytes:
    ident = _media_id(kind, device_id)
    return _sdnk(
        TYPE_PUNCH,
        bytes((1, sequence & 0xFF)) + ident + ident,
    )


def _connect_packet(attempt: int = 1) -> bytes:
    return _sdnk(TYPE_CONNECT, bytes((attempt & 0xFF,)))


def _parse_peer_packet(data: bytes) -> list[tuple[str, int]]:
    if len(data) != 110 or data[:4] != MAGIC or data[7] != TYPE_PEERS:
        return []
    endpoints: list[tuple[str, int]] = []
    for offset in range(20, 108, 22):
        address_bytes = data[offset : offset + 4]
        port = struct.unpack_from(">H", data, offset + 20)[0]
        if any(address_bytes) and port:
            endpoints.append((".".join(str(value) for value in address_bytes), port))
    return endpoints


def _private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def _decrypt(key: str, blob: bytes) -> bytes:
    if len(key) != 16 or len(blob) < 32:
        raise ValueError("invalid encrypted media")
    decryptor = Cipher(
        algorithms.AES(key.encode("ascii")),
        modes.CBC(blob[:16]),
    ).decryptor()
    padded = decryptor.update(blob[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _local_address(remote: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((remote, 9))
        return str(sock.getsockname()[0])
    finally:
        sock.close()


class _ChannelProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "P2PVideoSession", control: bool) -> None:
        self.owner = owner
        self.control = control

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.owner._on_message(self.control, data, addr)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug(
            "MyQ camera UDP socket error (channel=%s, error_type=%s)",
            "control" if self.control else "media",
            type(exc).__name__,
        )


class P2PVideoSession:
    def __init__(
        self,
        camera: TendCamera,
        info: ConnectionInfo,
        on_record: RecordCallback,
    ) -> None:
        self.camera = camera
        self.info = info
        self._on_record = on_record
        self._transports: dict[bool, asyncio.DatagramTransport] = {}
        self._peers: dict[bool, tuple[str, int] | None] = {False: None, True: None}
        self._connected: dict[bool, bool] = {False: False, True: False}
        self._peer_selection: dict[bool, str] = {False: "none", True: "none"}
        self._punch_complete = False
        self._local_ip = ""
        self._frame_number: int | None = None
        self._fragments: list[bytes] = []
        self._closed = False
        self._stats: dict[str, int] = {
            "media_datagrams": 0,
            "control_datagrams": 0,
            "sdnk_packets": 0,
            "sdnk_peers": 0,
            "sdnk_punch": 0,
            "sdnk_connect": 0,
            "sdnk_connected": 0,
            "sdnk_other": 0,
            "media_fragments": 0,
            "rtp_packets": 0,
            "payload_packets": 0,
            "encrypted_payloads": 0,
            "decrypt_failures": 0,
            "records": 0,
            "post_punch_media_datagrams": 0,
            "post_punch_control_datagrams": 0,
            "post_punch_sdnk_packets": 0,
            "post_punch_media_fragments": 0,
            "post_punch_control_payloads": 0,
        }

    @property
    def diagnostics(self) -> dict[str, int | bool]:
        return {
            **self._stats,
            "media_connected": self._connected[False],
            "control_connected": self._connected[True],
            "media_peer_exact_local": self._peer_selection[False] == "exact_local",
            "media_peer_private_fallback": self._peer_selection[False] == "private_fallback",
            "media_peer_last_fallback": self._peer_selection[False] == "last_fallback",
            "control_peer_exact_local": self._peer_selection[True] == "exact_local",
            "control_peer_private_fallback": self._peer_selection[True] == "private_fallback",
            "control_peer_last_fallback": self._peer_selection[True] == "last_fallback",
        }

    async def async_punch(self, timeout: float = 8.0) -> None:
        if not self.info.relay_host or not self.info.relay_port:
            raise RuntimeError("camera relay endpoint missing")
        loop = asyncio.get_running_loop()
        media_sock: socket.socket | None = None
        control_sock: socket.socket | None = None
        for _ in range(100):
            media_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            media_sock.setblocking(False)
            media_sock.bind(("0.0.0.0", 0))
            port = media_sock.getsockname()[1]
            if port == 65535:
                media_sock.close()
                continue
            control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            control_sock.setblocking(False)
            try:
                control_sock.bind(("0.0.0.0", port + 1))
                break
            except OSError:
                media_sock.close()
                control_sock.close()
                media_sock = None
                control_sock = None
        if media_sock is None or control_sock is None:
            raise RuntimeError("camera UDP ports unavailable")

        self._local_ip = await asyncio.to_thread(_local_address, self.info.relay_host)
        media_transport, _ = await loop.create_datagram_endpoint(
            lambda: _ChannelProtocol(self, False), sock=media_sock
        )
        control_transport, _ = await loop.create_datagram_endpoint(
            lambda: _ChannelProtocol(self, True), sock=control_sock
        )
        self._transports[False] = media_transport
        self._transports[True] = control_transport

        deadline = loop.time() + timeout
        sequence = 0
        try:
            while not all(self._connected.values()):
                if self._closed:
                    raise RuntimeError("camera session closed")
                if loop.time() >= deadline:
                    raise TimeoutError("camera hole punch timed out")
                for control in (False, True):
                    transport = self._transports[control]
                    peer = self._peers[control]
                    if peer is None:
                        local_port = transport.get_extra_info("sockname")[1]
                        transport.sendto(
                            _register_packet(
                                "V",
                                self.camera.device_id,
                                self._local_ip,
                                local_port,
                                control,
                            ),
                            (self.info.relay_host, self.info.relay_port),
                        )
                    elif not self._connected[control]:
                        transport.sendto(
                            _punch_packet("V", self.camera.device_id, sequence), peer
                        )
                        transport.sendto(_connect_packet(), peer)
                sequence = min(sequence + 1, 2)
                await asyncio.sleep(0.1)
            self._punch_complete = True
        except Exception:
            self.close()
            raise

    def _on_message(
        self, control: bool, data: bytes, remote: tuple[str, int]
    ) -> None:
        if self._closed:
            return
        self._stats["control_datagrams" if control else "media_datagrams"] += 1
        if self._punch_complete:
            self._stats[
                "post_punch_control_datagrams" if control else "post_punch_media_datagrams"
            ] += 1
        transport = self._transports.get(control)
        if transport is None:
            return

        if len(data) >= 20 and data[:4] == MAGIC:
            self._stats["sdnk_packets"] += 1
            if self._punch_complete:
                self._stats["post_punch_sdnk_packets"] += 1
            packet_type = data[7]
            if packet_type == TYPE_PEERS:
                self._stats["sdnk_peers"] += 1
                endpoints = _parse_peer_packet(data)
                peer = next(
                    (
                        endpoint
                        for endpoint in endpoints
                        if endpoint[0] == self.camera.local_ip
                    ),
                    None,
                )
                selection = "exact_local" if peer is not None else "none"
                if peer is None:
                    peer = next(
                        (
                            endpoint
                            for endpoint in endpoints
                            if _private(endpoint[0])
                            and endpoint[0] != self._local_ip
                        ),
                        None,
                    )
                    if peer is not None:
                        selection = "private_fallback"
                if peer is None and endpoints:
                    peer = endpoints[-1]
                    selection = "last_fallback"
                self._peers[control] = peer
                self._peer_selection[control] = selection
                if peer is not None:
                    transport.sendto(
                        _relay_ack_packet("V", self.camera.device_id, control),
                        (self.info.relay_host, self.info.relay_port),
                    )
            elif packet_type == TYPE_PUNCH:
                self._stats["sdnk_punch"] += 1
                if self._connected[control]:
                    return
                self._peers[control] = remote
                for sequence in range(3):
                    transport.sendto(
                        _punch_packet("V", self.camera.device_id, sequence), remote
                    )
            elif packet_type == TYPE_CONNECT:
                self._stats["sdnk_connect"] += 1
                if self._connected[control]:
                    return
                self._peers[control] = remote
                payload = data[20:21] or b"\x01"
                transport.sendto(_sdnk(TYPE_CONNECTED, payload), remote)
            elif packet_type == TYPE_CONNECTED:
                self._stats["sdnk_connected"] += 1
                self._peers[control] = remote
                self._connected[control] = True
            else:
                self._stats["sdnk_other"] += 1
            return

        if not control:
            self._handle_media(data)
        elif self._punch_complete:
            self._stats["post_punch_control_payloads"] += 1

    def _handle_media(self, data: bytes) -> None:
        self._stats["media_fragments"] += 1
        if self._punch_complete:
            self._stats["post_punch_media_fragments"] += 1
        if len(data) < 8:
            return
        frame_number = struct.unpack_from("<I", data, 0)[0]
        if self._frame_number is None:
            self._frame_number = frame_number
        elif frame_number != self._frame_number:
            self._flush_rtp()
            self._frame_number = frame_number
        self._fragments.append(data[8:])

    def _flush_rtp(self) -> None:
        if not self._fragments:
            return
        rtp = b"".join(self._fragments)
        self._fragments.clear()
        if len(rtp) < 12 or rtp[0] >> 6 != 2:
            return
        self._stats["rtp_packets"] += 1
        self._process_payload(rtp[12:])

    def _process_payload(self, payload: bytes) -> None:
        if len(payload) < 10 or payload[:2] != b"w1":
            return
        self._stats["payload_packets"] += 1
        length = struct.unpack_from("<I", payload, 2)[0]
        if length + 6 != len(payload):
            return
        encrypted = ((payload[6] & 0xE0) >> 5) == 1
        combined_length = length - 4
        combined = payload[10 : 10 + combined_length]
        try:
            if encrypted:
                self._stats["encrypted_payloads"] += 1
                combined = _decrypt(self.info.aes_key, combined)
        except Exception:
            self._stats["decrypt_failures"] += 1
            _LOGGER.debug("MyQ camera media decrypt failed")
            return
        offset = 0
        while offset + 4 <= len(combined):
            record_length = struct.unpack_from("<I", combined, offset)[0]
            offset += 4
            end = offset + record_length
            if record_length <= 0 or end > len(combined):
                break
            self._stats["records"] += 1
            self._on_record(bytes(combined[offset:end]))
            offset = end

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._flush_rtp()
        for transport in self._transports.values():
            transport.close()
        self._transports.clear()
        self._peers = {False: None, True: None}
        self._connected = {False: False, True: False}
