import os
import base64
import hashlib
import json
import select
import socket
import struct
import threading
import time
import urllib.parse
import uuid
import re
from datetime import datetime
from pathlib import Path

import pymysql
from dotenv import load_dotenv
from active_broadcast_store import (
    active_broadcast_stop_requested,
    mark_active_broadcast_delivery,
    put_active_broadcast,
)
from endpoints import (
    ENDPOINT_PCM_FRAME_BYTES,
    ENDPOINT_PCM_SAMPLE_RATE,
    INTERNAL_STREAMING_CODEC_PCM,
    INTERNAL_STREAMING_CODEC_PCMU,
    configured_internal_streaming_codec,
    connect_endpoint_ipc,
    endpoint_pcm_to_ulaw,
    internal_streaming_uses_pcm,
    mix_endpoint_pcm_frames,
    normalize_endpoint_pcm_frame,
    ulaw_to_endpoint_pcm,
)
from clientd import (
    desktop_member_user_id,
    is_desktop_member_token,
    send_stream_frame,
    start_desktop_livepage,
    user_has_connected_client,
)
from group_features import (
    apply_all_recipients_policy,
    group_names_for_value,
    monitor_targets_for_rows,
    paging_tone_sequence,
    regular_group_targets,
    selected_group_rows,
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DEBUG = os.getenv("DEBUG", "").strip().lower() == "true"

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")

WS_HOST = os.getenv("LIVEPAGED_WS_HOST", "0.0.0.0")
WS_PORT = int(os.getenv("LIVEPAGED_WS_PORT", "50010"))
AUDIO_FRAME_BYTES = 160


def endpoint_stream_prepare_command(stream_id, group_id, targets, internal_codec):
    command = "PREPARELIVEPCM" if internal_streaming_uses_pcm(internal_codec) else "PREPARELIVE"
    return f"{command} {stream_id} {group_id} {' '.join(targets)}\n"


def page_debug(message):
    if DEBUG:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] livepaged {message}")


def rtp_socket_name(sock):
    try:
        host, port = sock.getsockname()[:2]
        return f"{host}:{port}"
    except Exception:
        return "unknown"


def latchable_rtp_packet(packet):
    if len(packet) < 12:
        return False
    if ((packet[:1] or b"\x00")[0] >> 6) != 2:
        return False
    packet_type = packet[1] if len(packet) > 1 else 0
    return not (192 <= packet_type <= 223)


def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        connect_timeout=10,
        read_timeout=10,
        write_timeout=10,
    )


def unique_tokens(values):
    tokens = []
    for value in values:
        token = str(value or "").strip()
        if token and token not in tokens:
            tokens.append(token)
    return tokens


def sip_extension_candidates(extension):
    token = str(extension or "").strip()
    candidates = [token]
    lowered = token.lower()
    if token.startswith("#"):
        candidates.append(token[1:])
        candidates.append("%23" + token[1:])
    elif lowered.startswith("%23"):
        candidates.append(token[3:])
        candidates.append("#" + token[3:])
    return unique_tokens(candidates)


def fetch_group_members(cur, group_id):
    target_list = set()
    for gid in str(group_id or "").split("."):
        gid = gid.strip()
        if not gid:
            continue
        cur.execute("SELECT members FROM groups WHERE id = %s", (gid,))
        row = cur.fetchone()
        page_debug(f"resolve_targets_group gid={gid!r} row={row}")
        if row and row[0]:
            for member in str(row[0]).replace(",", " ").split():
                if member:
                    target_list.add(member)
    return target_list


def resolve_group_rows(cur, group_id):
    resolved_group = resolve_group_value(cur, group_id)
    return resolved_group, selected_group_rows(cur, resolved_group)


def paging_targets_from_rows(rows):
    targets = []
    seen = set()
    for token in regular_group_targets(rows) + monitor_targets_for_rows(rows, "paging"):
        if token not in seen:
            seen.add(token)
            targets.append(token)
    return targets


def sanitize_identifier(name):
    return re.sub(r'[^a-zA-Z0-9_]', '', str(name))


def page_group_from_sip_input(cur, extension):
    try:
        cur.execute("SHOW COLUMNS FROM `endpoints-input-siptrunk`")
        columns = [str(row[0]) for row in cur.fetchall() if row and row[0]]
    except pymysql.MySQLError as exc:
        page_debug(f"sip_input_columns_error extension={extension!r} error={exc}")
        return ""
    if not columns:
        return ""

    lowered_columns = {column.lower(): column for column in columns}
    wanted = unique_tokens(
        [
            lowered_columns.get("extension", "extension"),
            lowered_columns.get("trigger", "trigger"),
            lowered_columns.get("group"),
            lowered_columns.get("groups"),
            lowered_columns.get("groupid"),
            lowered_columns.get("group_id"),
            lowered_columns.get("page_group"),
            lowered_columns.get("paging_group"),
        ]
    )
    existing = [column for column in wanted if column in columns]
    if not existing or "extension" not in lowered_columns:
        return ""

    extension_column = lowered_columns["extension"]
    selected_sql = ", ".join(f"`{sanitize_identifier(column)}`" for column in existing)
    safe_ext_col = sanitize_identifier(extension_column)
    
    for candidate in sip_extension_candidates(extension):
        cur.execute(
            f"SELECT {selected_sql} FROM `endpoints-input-siptrunk` WHERE `{safe_ext_col}` = %s LIMIT 1",
            (candidate,),
        )
        row = cur.fetchone()
        page_debug(f"sip_input_lookup extension={extension!r} candidate={candidate!r} row={row}")
        if not row:
            continue
        data = dict(zip(existing, row))
        for name in ("group", "groups", "groupid", "group_id", "page_group", "paging_group"):
            column = lowered_columns.get(name)
            value = str(data.get(column) or "").strip() if column else ""
            if value:
                return value
        trigger_column = lowered_columns.get("trigger")
        trigger = str(data.get(trigger_column) or "").strip() if trigger_column else ""
        if ":" in trigger:
            trigger_name, trigger_arg = trigger.split(":", 1)
            if trigger_name.strip().lower() == "page":
                return trigger_arg.strip()
    return ""


def resolve_group_value(cur, group_id):
    raw = str(group_id or "").strip()
    if raw == "0":
        return raw
    direct_members = fetch_group_members(cur, raw)
    if direct_members:
        return raw
    stored_group = page_group_from_sip_input(cur, raw)
    return str(stored_group or raw).strip()


def parse_rtp_payload(packet, payload_type=0):
    if len(packet) < 12:
        return b""
    if (packet[0] >> 6) != 2:
        return b""
    cc = packet[0] & 0x0F
    ext = (packet[0] & 0x10) >> 4
    padded = bool(packet[0] & 0x20)
    pt = packet[1] & 0x7F
    if pt != int(payload_type):
        return b""
    offset = 12 + cc * 4
    if ext:
        if len(packet) < offset + 4:
            return b""
        ext_len = int.from_bytes(packet[offset + 2:offset + 4], "big")
        offset += 4 + ext_len * 4
    payload_end = len(packet)
    if padded:
        padding_bytes = packet[-1]
        if padding_bytes <= 0 or padding_bytes > payload_end - offset:
            return b""
        payload_end -= padding_bytes
    if offset >= payload_end:
        return b""
    return packet[offset:payload_end]


def normalize_livepage_targets(targets):
    normalized = []
    seen = set()
    for target in targets or []:
        token = str(target or "").strip()
        if not token:
            continue
        lowered = token.lower()
        if lowered == "page":
            continue
        if lowered.startswith("page/"):
            token = token.split("/", 1)[1].strip()
            lowered = token.lower()
        if token and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


def resolve_targets(group_id):
    page_debug(f"resolve_targets_start group={group_id!r}")
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            allowed_groups, removed_all = apply_all_recipients_policy(group_id, cursor=cur)
            if removed_all and not allowed_groups:
                page_debug(f"resolve_targets_blocked_all group={group_id!r}")
                return "", []
            resolved_group, rows = resolve_group_rows(cur, allowed_groups)
            if resolved_group != str(group_id or "").strip():
                page_debug(f"resolve_targets_sip_input_group extension={group_id!r} stored_group={resolved_group!r}")
            targets = paging_targets_from_rows(rows)
            if not targets and str(resolved_group) == "0":
                try:
                    cur.execute("SELECT `dir` FROM endpointmodulesloaded WHERE enabled = 'true' AND trusted = 'true'")
                    rows = cur.fetchall()
                except Exception:
                    rows = []
                for row in rows:
                    if row and row[0]:
                        targets.append(f"{row[0]}/all")
            page_debug(f"resolve_targets_done group={group_id!r} resolved_group={resolved_group!r} targets={targets}")
            return resolved_group, targets
    except Exception as exc:
        page_debug(f"resolve_targets_error group={group_id!r} error={exc.__class__.__name__}: {exc}")
        raise
    finally:
        conn.close()


def endpoint_targets_only(targets):
    filtered = []
    for target in normalize_livepage_targets(targets):
        if is_desktop_member_token(target):
            continue
        filtered.append(target)
    return filtered


def connected_desktop_count(group_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            allowed_groups, removed_all = apply_all_recipients_policy(group_id, cursor=cur)
            if removed_all and not allowed_groups:
                return 0
            resolved_group, rows = resolve_group_rows(cur, allowed_groups)
            if resolved_group == "0" and not rows:
                cur.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE role IS NULL OR role = '' OR role NOT IN ('receiver', 'tempreceiver')
                    ORDER BY username ASC
                    """
                )
                rows = cur.fetchall()
                return sum(1 for row in rows if row and row[0] is not None and user_has_connected_client(row[0]))
        members = paging_targets_from_rows(rows)
        return sum(1 for member in members if is_desktop_member_token(member) and user_has_connected_client(desktop_member_user_id(member)))
    finally:
        conn.close()


class LivePageSession:
    def __init__(self, remote_ip, remote_port, group_id, generator=None, on_finish=None, sender=None):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.group_id = str(group_id) if group_id is not None else ""
        self.generator = generator
        self.on_finish = on_finish
        self.sender = "" if sender is None else str(sender)
        self.local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local_sock.bind(("0.0.0.0", 0))
        self.local_sock.settimeout(0.5)
        self.local_port = self.local_sock.getsockname()[1]
        self.control_sock = None
        self.endpoint_stream_pcm = False
        self.internal_streaming_codec = INTERNAL_STREAMING_CODEC_PCM
        self.desktop_stream_sock = None
        self.stream_id = uuid.uuid4().hex
        self.stop_event = threading.Event()
        self.thread = None
        self.resolved_group_id = self.group_id
        self.targets = []
        self.desktop_clients = 0
        self.group_names = []
        self.pre_tones = []
        self.post_tones = []
        self.cleanup_lock = threading.Lock()
        self.forward_lock = threading.Lock()
        self.pre_tone_mix_lock = threading.Lock()
        self.cleaned_up = False
        self.rtp_packets_received = 0
        self.rtp_paused = False
        self.pre_tone_active = False
        self.pre_tone_completed = False
        self.pre_tone_slot_frame = None
        self.pre_tone_slot_consumed = False
        self.end_requested = threading.Event()
        self.livepage_record_registered = False
        self.stop_monitor_thread = None
        self.cleanup_after_run = True
        self.skip_post_tones = False
        page_debug(
            f"session_init stream={self.stream_id} remote={self.remote_ip}:{self.remote_port} "
            f"group={self.group_id!r} sender={self.sender!r} local_port={self.local_port}"
        )

    def load_group_runtime_context(self):
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                self.group_names = group_names_for_value(cur, self.resolved_group_id)
                self.pre_tones = paging_tone_sequence(cur, self.resolved_group_id, "pre")
                self.post_tones = paging_tone_sequence(cur, self.resolved_group_id, "post")
        finally:
            conn.close()

    def register_livepage_record(self):
        if self.livepage_record_registered:
            return True
        record = {
            "id": self.stream_id,
            "name": "Live Page",
            "shortmessage": "",
            "longmessage": "",
            "icon": "fa-solid fa-microphone",
            "color": "#c62828",
            "vendor_specific": "",
            "template_id": "",
            "expires_rule": "manual",
            "type": "Page",
            "expires": None,
            "issued": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "groups": self.resolved_group_id,
            "image": "",
            "audio": "",
            "sender": self.sender or "Live Page",
            "priority": "Normal",
            "delivery": "live",
            "runtime_kind": "livepage",
        }
        try:
            put_active_broadcast(record)
            self.livepage_record_registered = True
            return True
        except Exception as exc:
            page_debug(
                f"livepage_record_register_error stream={self.stream_id} group={self.resolved_group_id!r} "
                f"error={exc.__class__.__name__}: {exc}"
            )
            return False

    def start_stop_request_monitor(self):
        if self.stop_monitor_thread is not None and self.stop_monitor_thread.is_alive():
            return

        def monitor():
            while not self.cleaned_up and not self.stop_event.is_set():
                try:
                    if active_broadcast_stop_requested(self.stream_id):
                        self.handle_external_stop_request()
                        return
                except Exception as exc:
                    page_debug(
                        f"livepage_stop_monitor_error stream={self.stream_id} "
                        f"error={exc.__class__.__name__}: {exc}"
                    )
                time.sleep(0.2)

        self.stop_monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.stop_monitor_thread.start()

    def enable_livepage_tracking(self):
        if self.register_livepage_record():
            self.start_stop_request_monitor()

    def request_end(self):
        self.end_requested.set()
        if not self.pre_tone_active:
            self.stop_event.set()

    def handle_external_stop_request(self):
        self.skip_post_tones = True
        self.stop()

    def forward_stream_audio(self, endpoint_data, desktop_data, ignore_pause=False, ignore_stop=False):
        if (self.stop_event.is_set() and not ignore_stop) or self.cleaned_up:
            return False
        if self.rtp_paused and not ignore_pause:
            return False
        endpoint_data = bytes(endpoint_data or b"")
        desktop_data = bytes(desktop_data or b"")
        if not endpoint_data and not desktop_data:
            return False
        with self.forward_lock:
            if self.control_sock is not None and endpoint_data:
                try:
                    self.control_sock.sendall(endpoint_data)
                except OSError as exc:
                    page_debug(
                        f"endpoint_audio_error stream={self.stream_id} resolved_group={self.resolved_group_id!r} "
                        f"error={exc.__class__.__name__}: {exc}"
                    )
                    try:
                        self.control_sock.close()
                    except OSError:
                        pass
                    self.control_sock = None
            try:
                if self.desktop_stream_sock is not None and desktop_data:
                    send_stream_frame(self.desktop_stream_sock, desktop_data)
            except Exception as exc:
                page_debug(
                    f"desktop_audio_error stream={self.stream_id} resolved_group={self.resolved_group_id!r} "
                    f"error={exc.__class__.__name__}: {exc}"
                )
        return True

    def forward_payload(self, payload, ignore_pause=False, ignore_stop=False):
        ulaw = bytes(payload or b"")
        if not ulaw:
            return False
        endpoint_data = ulaw_to_endpoint_pcm(ulaw) if self.endpoint_stream_pcm else ulaw
        desktop_data = endpoint_data if self.desktop_stream_sock is not None else b""
        return self.forward_stream_audio(
            endpoint_data,
            desktop_data,
            ignore_pause=ignore_pause,
            ignore_stop=ignore_stop,
        )

    def forward_pcm_payload(self, payload, ignore_pause=False, ignore_stop=False):
        pcm = bytes(payload or b"")
        if not pcm:
            return False
        complete = len(pcm) - (len(pcm) % ENDPOINT_PCM_FRAME_BYTES)
        if complete <= 0:
            return False
        pcm = pcm[:complete]
        needs_ulaw = not self.endpoint_stream_pcm
        ulaw = endpoint_pcm_to_ulaw(pcm) if needs_ulaw else b""
        endpoint_data = pcm if self.endpoint_stream_pcm else ulaw
        desktop_data = (pcm if self.endpoint_stream_pcm else ulaw) if self.desktop_stream_sock is not None else b""
        return self.forward_stream_audio(
            endpoint_data,
            desktop_data,
            ignore_pause=ignore_pause,
            ignore_stop=ignore_stop,
        )

    def normalize_audio_frame(self, payload):
        data = bytes(payload or b"")
        if not data:
            return b""
        if len(data) < AUDIO_FRAME_BYTES:
            return data.ljust(AUDIO_FRAME_BYTES, b"\xff")
        if len(data) > AUDIO_FRAME_BYTES:
            return data[:AUDIO_FRAME_BYTES]
        return data

    def begin_pre_tone_slot(self, frame):
        with self.pre_tone_mix_lock:
            if self.endpoint_stream_pcm:
                self.pre_tone_slot_frame = normalize_endpoint_pcm_frame(frame)
            elif len(frame or b"") == ENDPOINT_PCM_FRAME_BYTES:
                self.pre_tone_slot_frame = endpoint_pcm_to_ulaw(frame)
            else:
                self.pre_tone_slot_frame = self.normalize_audio_frame(frame)
            self.pre_tone_slot_consumed = False

    def finish_pre_tone_slot(self):
        frame = None
        with self.pre_tone_mix_lock:
            if self.pre_tone_slot_frame is not None and not self.pre_tone_slot_consumed:
                frame = self.pre_tone_slot_frame
            self.pre_tone_slot_frame = None
            self.pre_tone_slot_consumed = False
        if frame is not None:
            if self.endpoint_stream_pcm:
                self.forward_pcm_payload(frame, ignore_pause=True, ignore_stop=True)
            else:
                self.forward_payload(frame, ignore_pause=True, ignore_stop=True)

    def clear_pre_tone_slot(self):
        with self.pre_tone_mix_lock:
            self.pre_tone_slot_frame = None
            self.pre_tone_slot_consumed = False

    def mix_pre_tone_payload(self, payload):
        data = self.normalize_audio_frame(payload)
        if not data:
            return b""
        if not self.pre_tone_active:
            return data
        tone_frame = None
        with self.pre_tone_mix_lock:
            if self.pre_tone_active and self.pre_tone_slot_frame is not None and not self.pre_tone_slot_consumed:
                tone_frame = self.pre_tone_slot_frame
                self.pre_tone_slot_consumed = True
        if tone_frame is None:
            return ulaw_to_endpoint_pcm(data) if self.endpoint_stream_pcm else data
        if self.endpoint_stream_pcm:
            return mix_endpoint_pcm_frames([tone_frame, ulaw_to_endpoint_pcm(data)])
        from endpoints import mix_ulaw_frames

        return mix_ulaw_frames([tone_frame, data])

    def mix_pre_tone_pcm_payload(self, payload):
        data = normalize_endpoint_pcm_frame(payload, accept_legacy_ulaw=False)
        if not self.pre_tone_active:
            return data
        tone_frame = None
        with self.pre_tone_mix_lock:
            if self.pre_tone_active and self.pre_tone_slot_frame is not None and not self.pre_tone_slot_consumed:
                tone_frame = self.pre_tone_slot_frame
                self.pre_tone_slot_consumed = True
        if self.endpoint_stream_pcm:
            return mix_endpoint_pcm_frames([tone_frame, data]) if tone_frame is not None else data
        from endpoints import mix_ulaw_frames

        ulaw = endpoint_pcm_to_ulaw(data)
        return mix_ulaw_frames([tone_frame, ulaw]) if tone_frame is not None else ulaw

    def before_pre_tone_slot(self, _frame):
        return

    def inbound_payload_type(self):
        return 0

    def decode_inbound_payload(self, payload):
        return payload

    def forward_live_payload(self, payload):
        data = bytes(payload or b"")
        if not data:
            return False
        if self.pre_tone_active:
            mixed = self.mix_pre_tone_payload(data)
            if self.endpoint_stream_pcm:
                return self.forward_pcm_payload(mixed, ignore_pause=True)
            return self.forward_payload(mixed, ignore_pause=True)
        return self.forward_payload(data)

    def forward_live_pcm_payload(self, payload):
        data = bytes(payload or b"")
        if not data:
            return False
        if self.pre_tone_active:
            mixed = self.mix_pre_tone_pcm_payload(data)
            if not self.endpoint_stream_pcm:
                return self.forward_payload(mixed, ignore_pause=True)
            return self.forward_pcm_payload(mixed, ignore_pause=True)
        return self.forward_pcm_payload(data)

    def play_tone_sequence(self, tones):
        if not tones:
            return
        from endpoints import audio_frames, endpoint_pcm_audio_frames

        frame_source = endpoint_pcm_audio_frames if self.endpoint_stream_pcm else audio_frames
        frame_duration = 0.02
        next_send_time = time.perf_counter()
        for tone in tones:
            for frame in frame_source(tone):
                if self.endpoint_stream_pcm:
                    self.forward_pcm_payload(frame, ignore_pause=True, ignore_stop=True)
                else:
                    self.forward_payload(frame, ignore_pause=True, ignore_stop=True)
                next_send_time += frame_duration
                sleep_time = next_send_time - time.perf_counter()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                else:
                    next_send_time = time.perf_counter()

    def play_pre_tones(self):
        if not self.pre_tones:
            self.pre_tone_completed = True
            return
        self.pre_tone_active = True
        try:
            from endpoints import audio_frames, endpoint_pcm_audio_frames

            frame_source = endpoint_pcm_audio_frames if self.endpoint_stream_pcm else audio_frames
            frame_duration = 0.02
            next_send_time = time.perf_counter()
            for tone in self.pre_tones:
                for frame in frame_source(tone):
                    if self.stop_event.is_set() and not self.end_requested.is_set():
                        return
                    self.begin_pre_tone_slot(frame)
                    self.before_pre_tone_slot(frame)
                    next_send_time += frame_duration
                    sleep_time = next_send_time - time.perf_counter()
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                    else:
                        next_send_time = time.perf_counter()
                    self.finish_pre_tone_slot()
        finally:
            self.clear_pre_tone_slot()
            self.pre_tone_active = False
            self.pre_tone_completed = True
            if self.end_requested.is_set():
                self.stop_event.set()

    def play_post_tones(self):
        if self.skip_post_tones or not self.post_tones:
            return
        paused = self.rtp_paused
        self.rtp_paused = True
        try:
            self.play_tone_sequence(self.post_tones)
        finally:
            self.rtp_paused = paused

    def learn_rtp_source(self, addr, packet):
        if not getattr(self, "rtp_latching_enabled", False):
            return False
        if not addr or len(addr) < 2 or not latchable_rtp_packet(packet):
            return False
        source_ip = str(addr[0] or "").strip()
        try:
            source_port = int(addr[1] or 0)
        except Exception:
            source_port = 0
        current_port = int(getattr(self, "remote_port", 0) or 0)
        if (
            not source_ip
            or source_port <= 0
            or (current_port > 0 and current_port % 2 == 0 and source_port == current_port + 1 and source_port % 2 == 1)
        ):
            return False
        old_ip = str(getattr(self, "remote_ip", "") or "")
        old_port = int(getattr(self, "remote_port", 0) or 0)
        self.remote_ip = source_ip
        self.remote_port = source_port
        if (old_ip, old_port) != (source_ip, source_port):
            page_debug(
                f"rtp_latch stream={self.stream_id} local={rtp_socket_name(self.local_sock)} "
                f"old={old_ip}:{old_port} new={source_ip}:{source_port}"
            )
        return True

    def preflight(self):
        page_debug(f"preflight_start stream={self.stream_id} group={self.group_id!r}")
        self.resolved_group_id, self.targets = resolve_targets(self.group_id)
        self.load_group_runtime_context()
        try:
            self.desktop_clients = connected_desktop_count(self.group_id)
        except Exception as exc:
            self.desktop_clients = 0
            page_debug(
                f"desktop_count_error stream={self.stream_id} group={self.group_id!r} "
                f"resolved_group={self.resolved_group_id!r} error={exc.__class__.__name__}: {exc}"
            )
        endpoint_targets = endpoint_targets_only(self.targets)
        if not endpoint_targets and self.desktop_clients <= 0:
            page_debug(f"preflight_no_targets stream={self.stream_id} group={self.group_id!r}")
            raise RuntimeError("503 Service Unavailable")
        self.internal_streaming_codec = configured_internal_streaming_codec()
        self.endpoint_stream_pcm = internal_streaming_uses_pcm(self.internal_streaming_codec)
        if endpoint_targets:
            try:
                self.control_sock = connect_endpoint_ipc(timeout=10)
                command = endpoint_stream_prepare_command(
                    self.stream_id,
                    self.group_id,
                    endpoint_targets,
                    self.internal_streaming_codec,
                )
                page_debug(
                    f"preflight_connect stream={self.stream_id} command={command.strip()!r}"
                )
                self.control_sock.sendall(command.encode("utf-8"))
                response = self.control_sock.recv(1024)
                page_debug(f"preflight_response stream={self.stream_id} response={response!r}")
                if b"OK" not in response:
                    raise RuntimeError("endpoint targets not ready")
            except Exception as exc:
                page_debug(
                    f"preflight_endpoint_error stream={self.stream_id} group={self.group_id!r} "
                    f"error={exc.__class__.__name__}: {exc}"
                )
                try:
                    if self.control_sock is not None:
                        self.control_sock.close()
                except OSError:
                    pass
                self.control_sock = None
                if self.desktop_clients <= 0:
                    raise RuntimeError("503 Service Unavailable")
        try:
            self.desktop_stream_sock, result = start_desktop_livepage(
                self.stream_id,
                self.resolved_group_id,
                self.sender or "Live Page",
                codec=self.internal_streaming_codec if self.endpoint_stream_pcm else "mulaw",
                sample_rate=ENDPOINT_PCM_SAMPLE_RATE if self.endpoint_stream_pcm else 8000,
            )
            self.desktop_clients = int((result or {}).get("matched") or 0)
        except Exception as exc:
            page_debug(
                f"desktop_start_error stream={self.stream_id} group={self.group_id!r} "
                f"resolved_group={self.resolved_group_id!r} error={exc.__class__.__name__}: {exc}"
            )
            self.desktop_clients = 0
        if self.control_sock is None and self.desktop_clients <= 0:
            page_debug(f"preflight_no_working_targets stream={self.stream_id} group={self.group_id!r}")
            raise RuntimeError("503 Service Unavailable")
        page_debug(f"preflight_ok stream={self.stream_id}")

    def start(self):
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def run(self):
        packets = 0
        bytes_sent = 0
        keepalive_payload = getattr(self, "rtp_keepalive_payload", None)
        next_keepalive = time.monotonic()
        if keepalive_payload and hasattr(self, "send_rtp"):
            try:
                self.local_sock.setblocking(False)
            except OSError:
                pass
        try:
            while not self.stop_event.is_set():
                try:
                    local_sock = self.local_sock
                    if local_sock is None:
                        break
                    if keepalive_payload and hasattr(self, "send_rtp"):
                        now = time.monotonic()
                        wait = max(0.0, min(0.02, next_keepalive - now))
                        ready, _, _ = select.select([local_sock], [], [], wait)
                        if not ready:
                            now = time.monotonic()
                            if now >= next_keepalive:
                                try:
                                    self.send_rtp(keepalive_payload, poll_source=False)
                                except TypeError:
                                    self.send_rtp(keepalive_payload)
                                next_keepalive = now + 0.02
                            continue
                    packet, addr = local_sock.recvfrom(4096)
                except (AttributeError, ValueError):
                    break
                except socket.timeout:
                    continue
                except BlockingIOError:
                    time.sleep(0.005)
                    continue
                except OSError:
                    break
                self.rtp_packets_received += 1
                if self.rtp_packets_received <= 3 or self.rtp_packets_received % 50 == 0:
                    page_debug(
                        f"rtp_recv stream={self.stream_id} packet={self.rtp_packets_received} "
                        f"local={rtp_socket_name(self.local_sock)} remote={addr[0]}:{addr[1]} bytes={len(packet)}"
                    )
                self.learn_rtp_source(addr, packet)
                payload = parse_rtp_payload(packet, self.inbound_payload_type())
                if not payload:
                    continue
                payload = self.decode_inbound_payload(payload)
                if not payload:
                    continue
                try:
                    self.forward_live_payload(payload)
                    packets += 1
                    bytes_sent += len(payload)
                    if packets == 1 or packets % 50 == 0:
                        page_debug(
                            f"audio_forward stream={self.stream_id} packets={packets} "
                            f"bytes={bytes_sent} last_payload={len(payload)} desktop_clients={self.desktop_clients}"
                        )
                except OSError:
                    break
        finally:
            page_debug(
                f"run_end stream={self.stream_id} packets={packets} bytes={bytes_sent} "
                f"rtp_sent={getattr(self, 'rtp_packets_sent', 0)} rtp_recv={getattr(self, 'rtp_packets_received', 0)}"
            )
            if self.cleanup_after_run:
                self.cleanup()

    def stop(self):
        self.stop_event.set()
        self.cleanup()

    def cleanup(self):
        self.stop_event.set()
        with self.cleanup_lock:
            if self.cleaned_up:
                return
            self.cleaned_up = True
        try:
            if self.local_sock is not None:
                self.local_sock.close()
        except OSError:
            pass
        self.local_sock = None
        try:
            if self.control_sock is not None:
                self.control_sock.close()
        except OSError:
            pass
        self.control_sock = None
        try:
            if self.desktop_stream_sock is not None:
                self.desktop_stream_sock.close()
        except OSError:
            pass
        self.desktop_stream_sock = None
        if self.livepage_record_registered:
            try:
                mark_active_broadcast_delivery(self.stream_id, "stopped")
            except Exception as exc:
                page_debug(
                    f"livepage_record_cleanup_error stream={self.stream_id} "
                    f"error={exc.__class__.__name__}: {exc}"
                )
            self.livepage_record_registered = False
        if self.on_finish is not None:
            try:
                self.on_finish()
            except Exception:
                pass
        page_debug(f"cleanup stream={self.stream_id}")


class WebLivePageSession(LivePageSession):
    def __init__(self, *args, source_codec=INTERNAL_STREAMING_CODEC_PCMU, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_pcm = str(source_codec or "").strip().lower() == INTERNAL_STREAMING_CODEC_PCM

    def start(self):
        return

    def begin(self, websocket_conn):
        threading.Thread(target=self.enable_livepage_tracking, daemon=True).start()
        if not self.pre_tones:
            self.pre_tone_completed = True
            return

        def run_pre_tones():
            try:
                self.play_pre_tones()
                if not self.end_requested.is_set():
                    send_ws_json(websocket_conn, {"type": "pretone_done"})
            except Exception as exc:
                page_debug(
                    f"websocket_pretone_error stream={self.stream_id} error={exc.__class__.__name__}: {exc}"
                )

        threading.Thread(target=run_pre_tones, daemon=True).start()

    def finish_page(self):
        self.request_end()
        if self.pre_tone_active:
            timeout_counter = 100
            while self.pre_tone_active and not self.cleaned_up and timeout_counter > 0:
                time.sleep(0.05)
                timeout_counter -= 1
            self.cleanup()
            return
        self.play_post_tones()
        self.cleanup()

    def send_payload(self, payload):
        if self.source_pcm:
            self.forward_live_pcm_payload(payload)
        else:
            self.forward_live_payload(payload)

def recv_until(sock, marker, limit=8192):
    data = b""
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    return data


def websocket_accept_key(key):
    source = (key.strip() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    return base64.b64encode(hashlib.sha1(source).digest()).decode("ascii")


def send_ws_frame(sock, opcode, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length <= 0xFFFF:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    sock.sendall(bytes(header) + payload)


def send_ws_json(sock, payload):
    send_ws_frame(sock, 0x1, json.dumps(payload))


def read_ws_exact(sock, length):
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    return payload


def read_ws_frame(sock):
    header = read_ws_exact(sock, 2)
    if len(header) < 2:
        return None, b""
    first, second = header
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        extended = read_ws_exact(sock, 2)
        if len(extended) < 2:
            return None, b""
        length = struct.unpack("!H", extended)[0]
    elif length == 127:
        extended = read_ws_exact(sock, 8)
        if len(extended) < 8:
            return None, b""
        length = struct.unpack("!Q", extended)[0]
    mask = read_ws_exact(sock, 4) if masked else b""
    if masked and len(mask) < 4:
        return None, b""
    payload = read_ws_exact(sock, length)
    if len(payload) < length:
        return None, b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def parse_ws_request(request):
    text = request.decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    if not lines:
        return "", {}, {}
    request_line = lines[0].split()
    path = request_line[1] if len(request_line) >= 2 else "/"
    parsed = urllib.parse.urlparse(path)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return parsed.path, urllib.parse.parse_qs(parsed.query), headers


def clean_group_id(value):
    value = str(value or "").strip()
    if value == "0":
        return value
    parts = []
    for part in value.split("."):
        part = part.strip()
        if part.isdigit():
            parts.append(part)
    return ".".join(parts)


def handle_websocket_client(conn, addr, request=None):
    session = None
    try:
        request = request if request is not None else recv_until(conn, b"\r\n\r\n")
        path, query, headers = parse_ws_request(request)
        key = str(headers.get("sec-websocket-key", "")).strip()
        group_id = clean_group_id((query.get("groups") or [""])[0])
        sender = str((query.get("sender") or ["Web Page"])[0]).strip()[:100]
        source_codec = str((query.get("codec") or [INTERNAL_STREAMING_CODEC_PCMU])[0]).strip().lower()
        if source_codec not in {INTERNAL_STREAMING_CODEC_PCM, INTERNAL_STREAMING_CODEC_PCMU}:
            source_codec = INTERNAL_STREAMING_CODEC_PCMU
        if path != "/live" or not key or not group_id:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {websocket_accept_key(key)}\r\n\r\n"
        )
        conn.sendall(response.encode("ascii"))
        session = WebLivePageSession(addr[0], 0, group_id=group_id, sender=sender, source_codec=source_codec)
        try:
            session.preflight()
        except Exception as exc:
            page_debug(f"websocket_preflight_error addr={addr} group={group_id!r} error={exc}")
            send_ws_json(conn, {"type": "error", "message": "Unable to start live page."})
            return
        send_ws_json(conn, {"type": "ready", "stream_id": session.stream_id, "pretone": bool(session.pre_tones)})
        session.begin(conn)
        try:
            conn.settimeout(10)
        except OSError:
            pass
        while True:
            if session.end_requested.is_set() or session.stop_event.is_set():
                break
            has_buffered = hasattr(conn, "pending") and conn.pending() > 0
            if not has_buffered:
                try:
                    ready, _, _ = select.select([conn], [], [], 0.25)
                except (ValueError, OSError):
                    break
                if not ready:
                    continue
            try:
                opcode, payload = read_ws_frame(conn)
            except (socket.timeout, TimeoutError):
                break
            except BlockingIOError:
                continue
            if opcode is None or opcode == 0x8:
                break
            if opcode == 0x9:
                send_ws_frame(conn, 0xA, payload)
                continue
            if opcode == 0x2:
                session.send_payload(payload)
    except Exception as exc:
        page_debug(f"websocket_client_error addr={addr} error={exc.__class__.__name__}: {exc}")
    finally:
        if session is not None:
            session.finish_page()
        try:
            send_ws_frame(conn, 0x8, b"")
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def serve_websocket():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((WS_HOST, WS_PORT))
    server.listen(25)
    page_debug(f"websocket_server_start host={WS_HOST} port={WS_PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_websocket_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    serve_websocket()
