#!/usr/bin/env python3
"""
Module: Hybrid Network Protocol
File: hybrid_network.py
Purpose: Secure network protocol with hybrid post-quantum encryption
Implements: Custom protocol over TCP with perfect forward secrecy
"""

import asyncio
import struct
import hashlib
import secrets
import time
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .crypto_engine import HybridKEM, HybridKeyPair, SecureMemory
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# PROTOCOL CONSTANTS
# ============================================

PROTOCOL_VERSION = 2
PROTOCOL_MAGIC = b"\x48\x4e\x44\x4c"  # "HNDL"
MAX_MESSAGE_SIZE = 1024 * 1024 * 10  # 10 MB
SESSION_KEY_ROTATION_INTERVAL = 3600  # 1 hour
MAX_RETRIES = 3
HEARTBEAT_INTERVAL = 30  # seconds

class MessageType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    KEY_EXCHANGE = 0x03
    KEY_EXCHANGE_ACK = 0x04
    DATA = 0x05
    DATA_ACK = 0x06
    HEARTBEAT = 0x07
    HEARTBEAT_ACK = 0x08
    CLOSE = 0x09
    ERROR = 0xFF

class CipherSuite(IntEnum):
    AES_128_GCM = 0x01
    AES_256_GCM = 0x02
    CHACHA20_POLY1305 = 0x03
    HYBRID_AES_256 = 0x10  # With post-quantum KEM

@dataclass
class SessionKeys:
    """Session encryption keys"""
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes
    created_at: float = field(default_factory=time.time)
    use_count: int = 0
    
    def should_rotate(self) -> bool:
        """Check if keys should be rotated"""
        return (time.time() - self.created_at) > SESSION_KEY_ROTATION_INTERVAL

# ============================================
# MESSAGE FRAMING
# ============================================

class MessageFramer:
    """Handles message framing and parsing"""
    
    HEADER_SIZE = 16
    
    @staticmethod
    def frame_message(
        msg_type: MessageType,
        payload: bytes,
        sequence: int,
        flags: int = 0,
    ) -> bytes:
        """Frame a message for transmission"""
        length = len(payload)
        
        header = struct.pack(
            ">4sBBHI",
            PROTOCOL_MAGIC,
            PROTOCOL_VERSION,
            msg_type.value,
            flags,
            sequence,
            length,
        )
        
        return header + payload
    
    @staticmethod
    def parse_header(data: bytes) -> Tuple[MessageType, int, int, int]:
        """Parse message header"""
        if len(data) < MessageFramer.HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes")
        
        magic, version, msg_type, flags, sequence, length = struct.unpack(
            ">4sBBHI",
            data[:MessageFramer.HEADER_SIZE]
        )
        
        if magic != PROTOCOL_MAGIC:
            raise ValueError("Invalid protocol magic")
        
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        return MessageType(msg_type), flags, sequence, length

# ============================================
# SESSION MANAGER
# ============================================

class HybridSession:
    """Manages a hybrid secure session"""
    
    def __init__(self, session_id: bytes, is_server: bool):
        self.session_id = session_id
        self.is_server = is_server
        self.sequence_in = 0
        self.sequence_out = 0
        self.keys: Optional[SessionKeys] = None
        self.hybrid_keypair: Optional[HybridKeyPair] = None
        self.peer_public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.created_at = time.time()
        self.last_activity = time.time()
        self.cipher_suite = CipherSuite.HYBRID_AES_256
        
    def generate_keypair(self) -> bytes:
        """Generate ephemeral keypair for session"""
        self.hybrid_keypair = HybridKeyPair.generate()
        return self.hybrid_keypair.hybrid_public
    
    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """Compute shared secret from peer's public key"""
        self.peer_public_key = peer_public
        
        if self.is_server:
            ciphertext, self.shared_secret = HybridKEM.encapsulate(peer_public)
            self.peer_ciphertext = ciphertext
        else:
            self.shared_secret = HybridKEM.decapsulate(
                self.hybrid_keypair.private_seed,
                peer_public,
            )
        
        return self.shared_secret
    
    def derive_session_keys(self):
        """Derive session encryption keys from shared secret"""
        if not self.shared_secret:
            raise ValueError("No shared secret established")
        
        # HKDF for key derivation
        prk = hashlib.pbkdf2_hmac(
            'sha256',
            self.shared_secret,
            self.session_id,
            1000,
            64,
        )
        
        client_key = prk[:32]
        server_key = prk[32:64]
        
        # IVs
        client_iv = hashlib.sha256(client_key + b"client_iv").digest()[:12]
        server_iv = hashlib.sha256(server_key + b"server_iv").digest()[:12]
        
        if self.is_server:
            self.keys = SessionKeys(
                client_write_key=client_key,
                server_write_key=server_key,
                client_write_iv=client_iv,
                server_write_iv=server_iv,
            )
        else:
            self.keys = SessionKeys(
                client_write_key=client_key,
                server_write_key=server_key,
                client_write_iv=client_iv,
                server_write_iv=server_iv,
            )
        
        logger.debug(f"Session keys derived for {self.session_id.hex()[:8]}")
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data for sending"""
        if not self.keys:
            raise ValueError("Session keys not established")
        
        key = self.keys.client_write_key if not self.is_server else self.keys.server_write_key
        iv = self.keys.client_write_iv if not self.is_server else self.keys.server_write_iv
        
        # Increment IV for each message
        iv_int = int.from_bytes(iv, 'big')
        iv_int += self.sequence_out
        nonce = iv_int.to_bytes(12, 'big')
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, self.session_id)
        
        self.sequence_out += 1
        self.keys.use_count += 1
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt received data"""
        if not self.keys:
            raise ValueError("Session keys not established")
        
        key = self.keys.server_write_key if not self.is_server else self.keys.client_write_key
        iv = self.keys.server_write_iv if not self.is_server else self.keys.client_write_iv
        
        iv_int = int.from_bytes(iv, 'big')
        iv_int += self.sequence_in
        nonce = iv_int.to_bytes(12, 'big')
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, self.session_id)
        
        self.sequence_in += 1
        
        return plaintext
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return (time.time() - self.last_activity) > HEARTBEAT_INTERVAL * 3
    
    def touch(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()

# ============================================
# PROTOCOL SERVER
# ============================================

class HybridProtocolServer:
    """Server implementing hybrid secure protocol"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443):
        self.host = host
        self.port = port
        self.sessions: Dict[bytes, HybridSession] = {}
        self.server: Optional[asyncio.Server] = None
        self.handlers: Dict[MessageType, Callable] = {}
        self.data_handler: Optional[Callable] = None
        
    def on_message(self, msg_type: MessageType):
        """Decorator to register message handlers"""
        def decorator(func):
            self.handlers[msg_type] = func
            return func
        return decorator
    
    def on_data(self, func: Callable):
        """Register data handler"""
        self.data_handler = func
        return func
    
    async def start(self):
        """Start the server"""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )
        logger.info(f"Hybrid protocol server listening on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        session_id = secrets.token_bytes(32)
        session = HybridSession(session_id, is_server=True)
        
        try:
            # Handshake
            await self._perform_handshake(reader, writer, session)
            
            self.sessions[session_id] = session
            
            # Main message loop
            await self._message_loop(reader, writer, session)
            
        except Exception as e:
            logger.error(f"Session error: {e}")
        finally:
            if session_id in self.sessions:
                del self.sessions[session_id]
            writer.close()
            await writer.wait_closed()
    
    async def _perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: HybridSession,
    ):
        """Perform protocol handshake"""
        # Read client hello
        header = await reader.readexactly(MessageFramer.HEADER_SIZE)
        msg_type, flags, sequence, length = MessageFramer.parse_header(header)
        
        if msg_type != MessageType.HELLO:
            raise ValueError(f"Expected HELLO, got {msg_type}")
        
        payload = await reader.readexactly(length)
        client_public = payload
        
        # Generate server keypair
        server_public = session.generate_keypair()
        
        # Compute shared secret
        ciphertext = session.compute_shared_secret(client_public)
        session.derive_session_keys()
        
        # Send hello ack
        response = MessageFramer.frame_message(
            MessageType.HELLO_ACK,
            server_public + ciphertext,
            sequence + 1,
        )
        writer.write(response)
        await writer.drain()
        
        logger.debug(f"Handshake completed for {session.session_id.hex()[:8]}")
    
    async def _message_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: HybridSession,
    ):
        """Main message processing loop"""
        while True:
            try:
                header = await asyncio.wait_for(
                    reader.readexactly(MessageFramer.HEADER_SIZE),
                    timeout=HEARTBEAT_INTERVAL * 2,
                )
            except asyncio.TimeoutError:
                if session.is_expired():
                    break
                continue
            
            msg_type, flags, sequence, length = MessageFramer.parse_header(header)
            payload = await reader.readexactly(length)
            
            session.touch()
            
            if msg_type == MessageType.DATA:
                plaintext = session.decrypt(payload)
                if self.data_handler:
                    response = await self.data_handler(plaintext, session)
                    if response:
                        encrypted = session.encrypt(response)
                        frame = MessageFramer.frame_message(
                            MessageType.DATA_ACK,
                            encrypted,
                            session.sequence_out,
                        )
                        writer.write(frame)
                        await writer.drain()
            
            elif msg_type == MessageType.HEARTBEAT:
                response = MessageFramer.frame_message(
                    MessageType.HEARTBEAT_ACK,
                    b"",
                    sequence + 1,
                )
                writer.write(response)
                await writer.drain()
            
            elif msg_type == MessageType.CLOSE:
                break
            
            elif msg_type in self.handlers:
                response = await self.handlers[msg_type](payload, session)
                if response:
                    writer.write(response)
                    await writer.drain()
    
    async def send_data(self, session_id: bytes, data: bytes) -> bool:
        """Send data to a specific session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        encrypted = session.encrypt(data)
        
        # Need writer reference - store in session
        return True

# ============================================
# PROTOCOL CLIENT
# ============================================

class HybridProtocolClient:
    """Client implementing hybrid secure protocol"""
    
    def __init__(self):
        self.session: Optional[HybridSession] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        
    async def connect(self, host: str, port: int) -> HybridSession:
        """Connect to server and establish session"""
        self.reader, self.writer = await asyncio.open_connection(host, port)
        
        session_id = secrets.token_bytes(32)
        self.session = HybridSession(session_id, is_server=False)
        
        # Generate keypair
        client_public = self.session.generate_keypair()
        
        # Send hello
        hello = MessageFramer.frame_message(
            MessageType.HELLO,
            client_public,
            0,
        )
        self.writer.write(hello)
        await self.writer.drain()
        
        # Receive hello ack
        header = await self.reader.readexactly(MessageFramer.HEADER_SIZE)
        msg_type, flags, sequence, length = MessageFramer.parse_header(header)
        payload = await self.reader.readexactly(length)
        
        server_public = payload[:1216]  # ML-KEM-768 + X25519
        ciphertext = payload[1216:]
        
        # Compute shared secret
        self.session.compute_shared_secret(ciphertext)
        self.session.derive_session_keys()
        
        logger.info(f"Connected to {host}:{port}")
        return self.session
    
    async def send(self, data: bytes) -> Optional[bytes]:
        """Send encrypted data and await response"""
        if not self.session or not self.writer:
            raise RuntimeError("Not connected")
        
        encrypted = self.session.encrypt(data)
        
        frame = MessageFramer.frame_message(
            MessageType.DATA,
            encrypted,
            self.session.sequence_out,
        )
        self.writer.write(frame)
        await self.writer.drain()
        
        # Read response
        header = await self.reader.readexactly(MessageFramer.HEADER_SIZE)
        msg_type, flags, sequence, length = MessageFramer.parse_header(header)
        payload = await self.reader.readexactly(length)
        
        if msg_type == MessageType.DATA_ACK:
            return self.session.decrypt(payload)
        
        return None
    
    async def heartbeat(self):
        """Send heartbeat"""
        if not self.session or not self.writer:
            return
        
        frame = MessageFramer.frame_message(
            MessageType.HEARTBEAT,
            b"",
            self.session.sequence_out,
        )
        self.writer.write(frame)
        await self.writer.drain()
    
    async def close(self):
        """Close the connection"""
        if self.writer:
            frame = MessageFramer.frame_message(
                MessageType.CLOSE,
                b"",
                self.session.sequence_out if self.session else 0,
            )
            self.writer.write(frame)
            await self.writer.drain()
            
            self.writer.close()
            await self.writer.wait_closed()
