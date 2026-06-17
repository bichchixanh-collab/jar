#!/usr/bin/env python3
"""
Binary String Translator
Scan, translate, and patch Chinese strings in binary files inside a .jar/.zip

Auto-detected formats per file:
  - len2be_utf8  : [2B BE len][MUTF-8]  — Java writeUTF / MUTF-8 (ưu tiên cao nhất)
  - len1_utf8    : [1B len][UTF-8]
  - len2le_utf8  : [2B LE len][UTF-8]
  - len1_gbk     : [1B len][GBK]
  - len2be_gbk   : [2B BE len][GBK]
  - null_utf8    : Null-terminated UTF-8
  - null_gbk     : Null-terminated GBK
  - xse          : XSE script format

Scan filter:
  - Chỉ xử lý extensions trong ALLOWED_EXTENSIONS
  - Bỏ files có magic bytes của ảnh/audio/zip/class
  - Loại bỏ strings có control bytes, tỷ lệ CJK thấp, hoặc quá dài
  - Java MUTF-8 detection tích hợp từ scanner.py (>= 8 fields → len2be)
"""

# import tkinter as tk  # removed for web
# from tkinter import ...  # removed for web
import threading
import zipfile
import struct
import os
import re
import time
from io import BytesIO
from collections import Counter

try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_OK = True
except ImportError:
    TRANSLATOR_OK = False

try:
    from unidecode import unidecode
    UNIDECODE_OK = True
except ImportError:
    UNIDECODE_OK = False


# ─────────────────────────────────────────────
# Chinese / Vietnamese detection
# ─────────────────────────────────────────────

RE_CHINESE = re.compile(
    r'[\u4e00-\u9fff'
    r'\u3400-\u4dbf'
    r'\uf900-\ufaff]'
)

RE_VIETNAMESE = re.compile(
    r'[ăắằẳẵặĂẮẰẲẴẶ'
    r'ơớờởỡợƠỚỜỞỠỢ'
    r'ưứừửữựƯỨỪỬỮỰ'
    r'đĐ'
    r'ấầẩẫậẤẦẨẪẬ'
    r'ếềểễệẾỀỂỄỆ'
    r'ốồổỗộỐỒỔỖỘ'
    r'ỉịỈỊ'
    r'ọỏỌỎ'
    r'ụủỤỦ'
    r'ỳỵỷỹỲỴỶỸ]'
)

def has_chinese(s: str) -> bool:
    return bool(RE_CHINESE.search(s))

def has_vietnamese(s: str) -> bool:
    return bool(RE_VIETNAMESE.search(s))

def has_target_language(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    return has_chinese(s) or has_vietnamese(s)


# ── String quality filter ──
_RE_PUA = re.compile(r'[\ue000-\uf8ff\ufff0-\uffff]')
_GARBAGE_CHARS = set(
    # □ (U+25A1) KHÔNG được đặt ở đây — xử lý riêng bằng box_ratio
    '■▪▫▬▭▮▯▰▱◆◇◈◉◊○◌◍◎●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯'
    # Replacement/unknown char
    '\ufffd'
    # Box drawing
    '─━│┃┄┅┆┇┈┉┊┋┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┯┰┱┲┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋'
    # Geometric shapes noise
    '▲△▴▵▶▷▸▹►▻▼▽▾▿◀◁◂◃◄◅'
)

def _is_meaningful_string(s: str) -> bool:
    """
    Lọc strings rác sau khi extract.

    Các rule theo thứ tự nghiêm ngặt tăng dần:
    1. Reject ký tự đặc biệt / garbage decode
    2. Reject chuỗi không có đủ CJK / Việt
    3. Reject tỷ lệ CJK thấp so với tổng chiều dài
    4. Reject dạng rác phổ biến: số/dấu thuần, CJK lặp, code/path
    5. Reject chuỗi mà phần lớn là ký tự Latin/ASCII không phải chữ thường
    """
    s = s.strip()
    if not s:
        return False

    total = len(s)
    cjk_chars = _CJK_TEXT_RE.findall(s)
    total_cjk = sum(len(c) for c in cjk_chars)
    viet_chars = len(RE_VIETNAMESE.findall(s))
    meaningful = total_cjk + viet_chars

    # ── Reject ngay: decode rõ ràng sai ──
    if _RE_PUA.search(s):
        return False
    if any(c in _GARBAGE_CHARS for c in s):
        return False
    if '\ufffd' in s:
        return False

    # □ (U+25A1) = decode sai
    box_count = s.count('\u25a1')
    if box_count > 0:
        if box_count / total > 0.15:       # > 15% là rác chắc chắn
            return False
        if total_cjk < 2 and viet_chars < 1:
            return False

    # ── Reject: quá ngắn + ít CJK ──
    # 1 CJK đơn độc
    if total_cjk == 1 and viet_chars == 0 and total <= 3:
        return False
    # Chuỗi ≤ 4 chars: phải có ≥ 2 CJK hoặc ≥ 2 Việt
    if total <= 4 and total_cjk < 2 and viet_chars < 2:
        return False
    # Chuỗi ≤ 8 chars: phải có ≥ 2 CJK hoặc ≥ 1 Việt
    if total <= 8 and total_cjk < 2 and viet_chars < 1:
        return False

    # ── Reject: dạng rác phổ biến ──
    # Thuần số/dấu/khoảng trắng
    if re.match(r'^[\d\s\-+()./#:,。、！？「」【】『』…·×÷=]+$', s):
        return False
    # CJK lặp liên tiếp >= 4 lần (noise/padding)
    if re.search(r'([\u4e00-\u9fff])\1{3,}', s):
        return False
    # Có vẻ là file path / resource key: chỉ ASCII + vài CJK
    if re.match(r'^[\w/\\.:\-]+$', s) and total_cjk < 2:
        return False
    # Dạng hex dump hoặc số hex
    if re.match(r'^[0-9a-fA-F\s]+$', s):
        return False

    # ── Reject: tỷ lệ CJK+Viet quá thấp ──
    # Với chuỗi dài, phần lớn phải là CJK/Việt để đáng dịch
    if total >= 6:
        ratio = meaningful / total
        if total_cjk >= 2:
            # Chuỗi có CJK: chấp nhận tỷ lệ thấp hơn vì có thể lẫn số/dấu
            # Ví dụ: "战斗力：100" → 3 CJK / 7 total = 43% → OK
            min_ratio = 0.20
        elif viet_chars >= 2:
            # Tiếng Việt thuần: ký tự ASCII + dấu kết hợp với viet chars — tỷ lệ thấp tự nhiên
            # Ví dụ: "Nhân vật của bạn" → viet_chars=2, total=16
            min_ratio = 0.08
        else:
            # Chỉ có 1-2 Việt: cần tỷ lệ cao hơn
            min_ratio = 0.25
        if ratio < min_ratio:
            return False

    # ── Reject: tỷ lệ ký tự "rác" (non-alpha, non-CJK) quá cao ──
    non_meaningful = sum(
        1 for c in s
        if not c.isalpha()
        and not ('\u4e00' <= c <= '\u9fff'
                 or '\u3400' <= c <= '\u4dbf'
                 or '\uf900' <= c <= '\ufaff')
        and c not in ' \t\r\n'
    )
    # Nếu > 60% là dấu/số/ký tự đặc biệt → rác
    # Nới lỏng khi CJK nhiều vì game hay có "攻击+10 防御+5" (số lẫn CJK)
    noise_threshold = 0.65 if total_cjk >= 3 else (0.55 if total_cjk >= 2 else 0.45)
    if total > 0 and non_meaningful / total > noise_threshold:
        return False

    # ── Reject: chuỗi toàn uppercase Latin + số + CJK ít ──
    # Ví dụ: "ABC123一" — kiểu resource key bị lẫn
    latin_upper = sum(1 for c in s if 'A' <= c <= 'Z')
    latin_lower = sum(1 for c in s if 'a' <= c <= 'z')
    if latin_upper > latin_lower and latin_upper > total_cjk and total_cjk < 3:
        return False

    return True

# Extensions được phép scan (giống scanner.py)
ALLOWED_EXTENSIONS = {'.bin', '.dat', '.res', '.pak', '.txt', '.ini', '.cfg',
                      '.xse', '.xs', '.scr', '.tbl', '.db', '.msg', '.arc'}

# Known binary magic signatures → skip (not scannable strings)
BINARY_MAGICS = [
    b'\x89PNG',           # PNG image
    b'\xff\xd8\xff',      # JPEG
    b'GIF8',              # GIF
    b'PK\x03\x04',        # ZIP/JAR nested
    b'\xca\xfe\xba\xbe',  # Java .class
    b'OggS',              # Ogg audio
    b'fLaC',              # FLAC audio
    b'ID3',               # MP3
    b'\x1f\x8b',          # gzip
    b'BZh',               # bzip2
    b'\x00\x00\x01\x00',  # ICO
    b'BM',                # BMP
    b'RIFF',              # WAV/AVI
    b'\x4d\x5a',          # Windows PE/EXE/DLL
    b'\x00\x00\x00\x0c\x6a\x50',  # JPEG2000
    b'#!',                # Shell script
]

# Regex CJK bytes (dùng chung với scoring & detection)
_CJK_UTF8_BYTES = re.compile(b'(?:[\xe4-\xe9][\x80-\xbf]{2})+')
_CJK_TEXT_RE    = re.compile(r'[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]+')


def _has_control_bytes(b: bytes) -> bool:
    """True nếu có control bytes (< 0x20) ngoài tab/newline/CR."""
    return any(c < 0x20 and c not in (0x09, 0x0a, 0x0d) for c in b)


def _binary_ratio(data: bytes) -> float:
    """Ratio của bytes trông như binary (control chars trừ tab/LF/CR)."""
    if not data:
        return 0.0
    sample = data[:4096]
    non_text = sum(1 for b in sample if b < 0x09 or (0x0e <= b <= 0x1f) or b == 0x7f)
    return non_text / len(sample)


def _count_java_mutf8_fields(data: bytes) -> int:
    """
    Đếm số embedded MUTF-8 fields hợp lệ: [2B BE len][UTF-8 content có CJK, không control].
    Quét từng byte để tìm tất cả candidates — dùng để detect encoding.
    """
    count = 0
    dlen  = len(data)
    MAX_FL = 1024
    for pos in range(dlen - 3):
        fl = int.from_bytes(data[pos:pos+2], 'big')
        if fl < 1 or fl > MAX_FL:
            continue
        end = pos + 2 + fl
        if end > dlen:
            continue
        chunk = data[pos+2:end]
        if not _CJK_UTF8_BYTES.search(chunk):
            continue
        if _has_control_bytes(chunk):
            continue
        try:
            chunk.decode('utf-8', errors='strict')
            count += 1
        except UnicodeDecodeError:
            pass
    return count


def is_structured_binary(data: bytes, filename: str = '') -> bool:
    """
    Returns True nếu file đáng scan strings.
    Reject: ảnh/audio/zip/class/media, file quá nhỏ, binary game data thuần.
    Accept: XML, UTF-16, game data có CJK strings, script binary, resource binary.
    """
    if len(data) < 6:
        return False

    # Skip theo magic bytes (image/audio/zip/exe) — KHÔNG skip UTF-16 BOM
    for magic in BINARY_MAGICS:
        if data.startswith(magic):
            return False

    # Blacklist extensions rõ ràng không chứa strings
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
                   '.mp3', '.ogg', '.wav', '.mid', '.aac',
                   '.class', '.jar', '.zip', '.gz', '.bz2',
                   '.map', '.palet', '.palette', '.pal', '.fnt', '.font',
                   '.tileset', '.tile', '.spr', '.sprite', '.anim',
                   '.idx', '.index', '.lut', '.raw'):
            return False

    # UTF-16 BOM → luôn accept
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return True

    # XML content → luôn accept
    sample_head = data[:256].lstrip()
    if sample_head.startswith(b'<?xml') or sample_head.startswith(b'<root') or \
       sample_head.startswith(b'<strings') or sample_head.startswith(b'<resources'):
        return True
    if filename and os.path.splitext(filename)[1].lower() == '.xml':
        return True

    # Phải có CJK: check UTF-8 bytes trước, fallback GBK byte range
    sample = data[:65536]
    if _CJK_UTF8_BYTES.search(sample):
        # Có CJK bytes — nhưng kiểm tra xem file có quá nhiều binary noise không
        # Nếu null_ratio > 40% VÀ CJK bytes rất ít so với file size → binary game data
        # (ví dụ: map file có 1 CJK string ở header rồi toàn tile binary data)
        cjk_matches = _CJK_UTF8_BYTES.findall(sample)
        cjk_byte_count = sum(len(m) for m in cjk_matches)
        null_count = data.count(b'\x00')
        null_ratio = null_count / len(data)
        # Nếu CJK bytes < 0.5% file size → có thể chỉ là header nhỏ trong binary lớn
        # Nhưng vẫn accept để extract_strings xử lý — detect_format sẽ chọn đúng format
        return True

    # Vietnamese UTF-8: multibyte sequences in Latin Extended range
    if re.search(b'[\xc3-\xc6\xe1][\x80-\xbf]', sample):
        viet_bytes = len(re.findall(b'[\xc3-\xc6\xe1\xe1][\x80-\xbf]', sample))
        if viet_bytes >= 3:
            return True

    # GBK CJK check: lead byte 0x81-0xFE followed by valid trail byte
    if re.search(b'[\x81-\xfe][\x40-\xfe]', sample):
        return True

    return False


# ── Format detection ──

FORMAT_UNKNOWN          = 'unknown'
FORMAT_LENGTH1_UTF8     = 'len1_utf8'    # [1B len][UTF-8]
FORMAT_LENGTH2_BE_UTF8  = 'len2be_utf8'  # [2B BE len][UTF-8]  — Java writeUTF / MUTF-8
FORMAT_LENGTH2_LE_UTF8  = 'len2le_utf8'  # [2B LE len][UTF-8]
FORMAT_LENGTH1_GBK      = 'len1_gbk'     # [1B len][GBK bytes]
FORMAT_LENGTH2_BE_GBK   = 'len2be_gbk'   # [2B BE len][GBK]
FORMAT_NULL_UTF8        = 'null_utf8'    # null-terminated UTF-8
FORMAT_NULL_GBK         = 'null_gbk'     # null-terminated GBK
FORMAT_XSE              = 'xse'          # XSE script: 2-byte LE offset table + strings
FORMAT_UTF16_LE         = 'utf16_le'     # UTF-16 Little Endian (BOM FF FE hoặc heuristic)
FORMAT_UTF16_BE         = 'utf16_be'     # UTF-16 Big Endian (BOM FE FF)
FORMAT_XML              = 'xml'          # XML file — parse text nodes/attributes

FORMAT_LABELS = {
    FORMAT_LENGTH1_UTF8:    '1B-len UTF-8',
    FORMAT_LENGTH2_BE_UTF8: '2B-len UTF-8 (Java)',
    FORMAT_LENGTH2_LE_UTF8: '2B-len UTF-8 (LE)',
    FORMAT_LENGTH1_GBK:     '1B-len GBK',
    FORMAT_LENGTH2_BE_GBK:  '2B-len GBK',
    FORMAT_NULL_UTF8:       'Null-term UTF-8',
    FORMAT_NULL_GBK:        'Null-term GBK',
    FORMAT_XSE:             'XSE Script',
    FORMAT_UTF16_LE:        'UTF-16 LE',
    FORMAT_UTF16_BE:        'UTF-16 BE',
    FORMAT_XML:             'XML',
    FORMAT_UNKNOWN:         'Unknown',
}

# Danh sách encodings phổ biến trong game J2ME Trung Quốc — hiển thị trong dropdown cột Format
# (label hiển thị → format key)
FORMAT_DROPDOWN_OPTIONS = [
    ('Auto-detect',          ''),            # placeholder, dùng detected value
    ('1B-len UTF-8',         FORMAT_LENGTH1_UTF8),
    ('2B-len UTF-8 (Java)',  FORMAT_LENGTH2_BE_UTF8),
    ('2B-len UTF-8 (LE)',    FORMAT_LENGTH2_LE_UTF8),
    ('1B-len GBK',           FORMAT_LENGTH1_GBK),
    ('2B-len GBK',           FORMAT_LENGTH2_BE_GBK),
    ('Null-term UTF-8',      FORMAT_NULL_UTF8),
    ('Null-term GBK',        FORMAT_NULL_GBK),
    ('UTF-16 LE',            FORMAT_UTF16_LE),
    ('UTF-16 BE',            FORMAT_UTF16_BE),
    ('XML',                  FORMAT_XML),
    ('BIG5 (1B-len)',        'len1_big5'),
    ('GB2312 (1B-len)',      'len1_gb2312'),
]
FORMAT_DROPDOWN_LABELS = [lbl for lbl, _ in FORMAT_DROPDOWN_OPTIONS[1:]]
FORMAT_LABEL_TO_KEY    = {lbl: key for lbl, key in FORMAT_DROPDOWN_OPTIONS[1:]}
FORMAT_KEY_TO_LABEL    = {key: lbl for lbl, key in FORMAT_DROPDOWN_OPTIONS[1:]}


def _score_format(data: bytes, fmt: str) -> int:
    """
    Chấm điểm format: số fields hợp lệ + kiểm tra tính nhất quán cấu trúc.

    Sliding-window extractors (len1/len2) dễ false-positive trên binary data ngẫu nhiên.
    Để phân biệt: trong file có format thật, các fields CJK phải **liên tiếp nhau**
    (end của field N ≈ start của field N+1, cách nhau tối đa vài bytes separator).
    Nếu các offsets rải rác khắp file → đây là noise, không phải format thật.
    """
    try:
        entries = _extract_with_format(data, fmt)
        if not entries:
            return 0

        # ── Bước 1: filter entries rác ──
        clean = []
        for offset, s, raw in entries:
            s = s.strip()
            if not s:
                continue
            cjk_chars = _CJK_TEXT_RE.findall(s)
            total_cjk = sum(len(c) for c in cjk_chars)
            viet_chars = len(RE_VIETNAMESE.findall(s))
            if total_cjk < 1 and viet_chars < 1:
                continue
            # String chứa replacement char → garbage decode
            if '\ufffd' in s:
                continue
            # Control bytes trong text → garbage
            if any(ord(c) < 32 and c not in '\r\n\t' for c in s):
                continue
            # Quá dài
            if len(s) > 300:
                continue
            clean.append((offset, s, raw, total_cjk + viet_chars))

        if not clean:
            return 0

        score = len(clean)

        # ── Bước 2: Consecutive field check (chỉ cho len-prefixed formats) ──
        # Nếu là len1/len2 format: kiểm tra xem các fields có nằm liên tiếp không.
        # Trong file thật, khoảng cách giữa end(field[i]) và start(field[i+1]) thường nhỏ.
        # Nếu hầu hết fields cách nhau > 64 bytes → likely noise từ sliding window.
        if fmt in (FORMAT_LENGTH1_UTF8, FORMAT_LENGTH1_GBK,
                   FORMAT_LENGTH2_BE_UTF8, FORMAT_LENGTH2_LE_UTF8, FORMAT_LENGTH2_BE_GBK):
            pfx = 1 if fmt in (FORMAT_LENGTH1_UTF8, FORMAT_LENGTH1_GBK) else 2

            if len(clean) >= 3:
                gaps = []
                for i in range(len(clean) - 1):
                    off_a, _, raw_a, _ = clean[i]
                    off_b = clean[i+1][0]
                    end_a = off_a + pfx + len(raw_a)
                    gap   = off_b - end_a
                    gaps.append(gap)

                # Tỷ lệ gaps nhỏ (≤ 16 bytes) — file thật thường > 50%
                small_gaps = sum(1 for g in gaps if 0 <= g <= 16)
                ratio_small = small_gaps / len(gaps)

                # GBK false-positive rate rất cao → threshold cao hơn UTF-8
                is_gbk_fmt = fmt in (FORMAT_LENGTH1_GBK, FORMAT_LENGTH2_BE_GBK)
                if is_gbk_fmt:
                    # GBK: phải có ít nhất 60% fields liên tiếp
                    if ratio_small < 0.40:
                        score = 0        # reject hoàn toàn
                    elif ratio_small < 0.60:
                        score = max(0, score // 3)
                else:
                    # UTF-8: nới lỏng hơn
                    if ratio_small < 0.25:
                        score = max(0, score // 4)
                    elif ratio_small < 0.50:
                        score = max(0, score // 2)

        return score

    except Exception:
        return 0


def _binary_density(data: bytes) -> float:
    """
    Tỷ lệ bytes ngoài (ASCII printable | CJK UTF-8 | null).
    KHÔNG đặc biệt xử lý GBK vì GBK bytes trong binary noise cũng là 2 bytes ngẫu nhiên.
    File binary thuần (offset tables, palettes, audio data) → density cao > 0.25.
    File game script/string table → density thấp hơn.
    Sample 4KB đầu để detect nhanh.
    """
    sample = data[:4096]
    if not sample:
        return 0.0
    noise = 0
    i = 0
    n = len(sample)
    while i < n:
        b = sample[i]
        # ASCII printable + whitespace → OK
        if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E:
            i += 1
            continue
        # Null byte (padding) → OK
        if b == 0x00:
            i += 1
            continue
        # CJK UTF-8 3-byte sequence → OK (valid UTF-8 CJK)
        if 0xE4 <= b <= 0xE9 and i + 2 < n:
            b2, b3 = sample[i+1], sample[i+2]
            if 0x80 <= b2 <= 0xBF and 0x80 <= b3 <= 0xBF:
                i += 3
                continue
        # Else: binary noise (kể cả GBK pairs — chúng sẽ được score riêng)
        noise += 1
        i += 1
    return noise / n


def detect_format(data: bytes, filename: str = '') -> str:
    """
    Auto-detect string encoding format của binary file.
    Ưu tiên: XML → UTF-16 (BOM) → Java MUTF-8 → len2/len1 UTF-8 → GBK → null-term.
    FORMAT_UNKNOWN không còn bị bỏ qua — fallback về null_utf8.
    """
    name_lower = filename.lower()

    # ── Step 0: XML file ──
    ext = os.path.splitext(name_lower)[1]
    if ext == '.xml':
        return FORMAT_XML
    # Detect XML bằng content (không extension)
    sample_head = data[:256].lstrip()
    if sample_head.startswith(b'<?xml') or sample_head.startswith(b'<root') or \
       sample_head.startswith(b'<strings') or sample_head.startswith(b'<resources'):
        return FORMAT_XML

    # XSE script files — by extension hoặc magic bytes
    # Format thực tế: [2B BE length][UTF-8 bytes][0x00 null terminator]
    # Java DataInputStream.readUTF() đọc length field → phải update length khi patch
    # → dùng FORMAT_LENGTH2_BE_UTF8 để patch_binary() ghi lại length field đúng
    if name_lower.endswith('.xse') or name_lower.endswith('.xs'):
        return FORMAT_LENGTH2_BE_UTF8
    # XSE magic: \x00\x04XSE0 tại byte 0
    if len(data) >= 6 and data[2:6] == b'XSE0':
        return FORMAT_LENGTH2_BE_UTF8

    # ── Step 1: UTF-16 detection — BOM trước, sau đó heuristic ──
    if len(data) >= 2:
        if data[:2] == b'\xff\xfe':
            return FORMAT_UTF16_LE   # BOM: UTF-16 LE
        if data[:2] == b'\xfe\xff':
            return FORMAT_UTF16_BE   # BOM: UTF-16 BE

    # Heuristic UTF-16 LE: nhiều cặp [byte hợp lệ][0x00] — đặc trưng text ASCII/Latin trong UTF-16 LE
    # QUAN TRỌNG: binary file có nhiều null bytes (map data, palette, offset tables) cũng trigger
    # heuristic này → phải validate decoded text chất lượng cao trước khi chấp nhận UTF-16
    if len(data) >= 8:
        sample_h = data[:2048]
        null_even = sum(1 for i in range(1, len(sample_h), 2) if sample_h[i] == 0)
        null_odd  = sum(1 for i in range(0, len(sample_h), 2) if sample_h[i] == 0)
        total_pairs = len(sample_h) // 2
        if total_pairs > 0:
            if null_even / total_pairs > 0.40:   # nhiều null ở byte lẻ → có thể UTF-16 LE
                try:
                    test = data[:1024].decode('utf-16-le', errors='replace')
                    t_len = len(test)
                    if t_len > 0:
                        cjk_ratio = sum(len(m) for m in _CJK_TEXT_RE.findall(test)) / t_len
                        ctrl_ratio = sum(1 for c in test if ord(c) < 0x20 and c not in '\t\n\r') / t_len
                        repl_ratio = test.count('\ufffd') / t_len
                        # UTF-16 thật: CJK phải chiếm đáng kể, ctrl thấp, ít replacement chars
                        if cjk_ratio >= 0.05 and ctrl_ratio < 0.30 and repl_ratio < 0.10:
                            return FORMAT_UTF16_LE
                except Exception:
                    pass
            if null_odd / total_pairs > 0.40:    # nhiều null ở byte chẵn → có thể UTF-16 BE
                try:
                    test = data[:1024].decode('utf-16-be', errors='replace')
                    t_len = len(test)
                    if t_len > 0:
                        cjk_ratio = sum(len(m) for m in _CJK_TEXT_RE.findall(test)) / t_len
                        ctrl_ratio = sum(1 for c in test if ord(c) < 0x20 and c not in '\t\n\r') / t_len
                        repl_ratio = test.count('\ufffd') / t_len
                        if cjk_ratio >= 0.05 and ctrl_ratio < 0.30 and repl_ratio < 0.10:
                            return FORMAT_UTF16_BE
                except Exception:
                    pass

    # Nếu null_ratio quá cao (>60%) mà không có CJK UTF-8 → skip
    null_ratio = data.count(b'\x00') / max(1, len(data))
    if null_ratio > 0.6 and not _CJK_UTF8_BYTES.search(data[:4096]):
        return FORMAT_UNKNOWN

    # ── Binary density: file có quá nhiều noise bytes → threshold cao hơn ──
    density = _binary_density(data)
    is_noisy = density > 0.30   # > 30% noise bytes → cần score cao hơn

    # ── Step 2: Java MUTF-8 — check đầu tiên ──
    mutf8_count = _count_java_mutf8_fields(data)
    mutf8_threshold = 8 if is_noisy else 5
    if mutf8_count >= mutf8_threshold:
        return FORMAT_LENGTH2_BE_UTF8

    # ── Step 3: Score các format ──
    candidates = [
        FORMAT_LENGTH2_BE_UTF8,
        FORMAT_LENGTH1_UTF8,
        FORMAT_LENGTH2_LE_UTF8,
        FORMAT_NULL_UTF8,
        FORMAT_LENGTH1_GBK,
        FORMAT_LENGTH2_BE_GBK,
    ]

    PRIORITY = [
        FORMAT_LENGTH2_BE_UTF8,
        FORMAT_LENGTH1_UTF8,
        FORMAT_LENGTH2_LE_UTF8,
        FORMAT_LENGTH1_GBK,
        FORMAT_LENGTH2_BE_GBK,
        FORMAT_NULL_UTF8,
        FORMAT_NULL_GBK,
    ]

    scores = {}
    for fmt in candidates:
        scores[fmt] = _score_format(data, fmt)

    best_score = max(scores.values()) if scores else 0

    if is_noisy:
        gbk_fmts = {FORMAT_LENGTH1_GBK, FORMAT_LENGTH2_BE_GBK,
                    FORMAT_NULL_GBK}
        for f in PRIORITY:
            s = scores.get(f, 0)
            if f in gbk_fmts and s >= 10:
                return f
            if f not in gbk_fmts and s >= 5:
                return f
        # Không đủ điểm → fallback heuristic thay vì bỏ qua
        # Thử null_utf8 trước (an toàn hơn)
        null_utf8_results = _extract_null_utf8(data)
        if null_utf8_results:
            return FORMAT_NULL_UTF8
        return FORMAT_UNKNOWN
    else:
        if best_score >= 5:
            return next(f for f in PRIORITY if scores.get(f, 0) == best_score)
        if best_score >= 3:
            return next(f for f in PRIORITY if scores.get(f, 0) == best_score)

    # ── Step 4: Last-resort fallback — thay vì trả UNKNOWN, thử null scan ──
    # File có bytes CJK UTF-8 nhưng không detect được format rõ → null_utf8
    if _CJK_UTF8_BYTES.search(data[:65536]):
        null_results = _extract_null_utf8(data)
        if null_results:
            return FORMAT_NULL_UTF8

    return FORMAT_UNKNOWN


# ── String extraction per format ──

def _try_decode(raw: bytes, encoding: str) -> str | None:
    """Try decoding bytes; return string or None."""
    try:
        s = raw.decode(encoding, errors='strict')
        return s if s.strip() else None
    except Exception:
        return None

def _decode_mutf8(raw: bytes) -> str | None:
    try:
        out = []
        i = 0
        n = len(raw)

        while i < n:
            b = raw[i]

            if b < 0x80:
                out.append(chr(b))
                i += 1

            elif (b & 0xE0) == 0xC0:
                if i + 1 >= n:
                    return None

                b2 = raw[i + 1]

                # Java Modified UTF-8 NULL
                if b == 0xC0 and b2 == 0x80:
                    out.append('\x00')
                else:
                    code = ((b & 0x1F) << 6) | (b2 & 0x3F)
                    out.append(chr(code))

                i += 2

            elif (b & 0xF0) == 0xE0:
                if i + 2 >= n:
                    return None

                b2 = raw[i + 1]
                b3 = raw[i + 2]

                code = (
                    ((b & 0x0F) << 12)
                    | ((b2 & 0x3F) << 6)
                    | (b3 & 0x3F)
                )

                out.append(chr(code))
                i += 3

            else:
                return None

        s = ''.join(out)
        return s if s.strip() else None

    except Exception:
        return None

def _extract_len1_utf8(data: bytes):
    """[1B len][UTF-8 bytes] — lấy chỉ fields có CJK, không control bytes."""
    results = []
    i = 0
    dlen = len(data)
    while i < dlen - 2:
        length = data[i]
        # Giới hạn 3..200 bytes để tránh bắt offset bảng / số ngẫu nhiên
        if 3 <= length <= 200:
            end = i + 1 + length
            if end <= dlen:
                raw = data[i+1:end]
                # Reject nếu có control bytes
                if _has_control_bytes(raw):
                    i += 1
                    continue
                s = _try_decode(raw, 'utf-8')
                if s and has_target_language(s) and '\ufffd' not in s and '\u25a1' not in s:
                    s_stripped = s.strip()
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s_stripped))
                    viet_count = len(RE_VIETNAMESE.findall(s_stripped))
                    slen = len(s_stripped)
                    # Stricter: chuỗi ngắn cần nhiều CJK hơn để chống noise
                    min_cjk = 3 if slen <= 3 else (2 if slen <= 8 else 1)
                    if cjk_count >= min_cjk or viet_count >= 2 or (viet_count >= 1 and cjk_count >= 1):
                        results.append((i, s_stripped or s, raw))
                        i = end
                        continue
        i += 1
    return results


def _extract_len2_utf8(data: bytes, big_endian: bool):
    """[2B len][UTF-8 bytes] — Java writeUTF (BE) hoặc LE variant."""
    fmt_str = '>H' if big_endian else '<H'
    results = []
    i = 0
    dlen = len(data)
    while i < dlen - 3:
        length = struct.unpack_from(fmt_str, data, i)[0]
        # Giới hạn 2..1024 bytes
        if 2 <= length <= 1024:
            end = i + 2 + length
            if end <= dlen:
                raw = data[i+2:end]
                # Reject nếu có control bytes
                if _has_control_bytes(raw):
                    i += 1
                    continue
                if big_endian:
                    s = _decode_mutf8(raw)
                else:
                    s = _try_decode(raw, 'utf-8')
                if s and has_target_language(s) and '\ufffd' not in s and '\u25a1' not in s:
                    s_stripped = s.strip()
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s_stripped))
                    viet_count = len(RE_VIETNAMESE.findall(s_stripped))
                    slen = len(s_stripped)
                    # Stricter: chuỗi ngắn cần nhiều CJK hơn
                    min_cjk = 3 if slen <= 3 else (2 if slen <= 8 else 1)
                    if cjk_count >= min_cjk or viet_count >= 2 or (viet_count >= 1 and cjk_count >= 1):
                        results.append((i, s_stripped or s, raw))
                        i = end
                        continue
        i += 1
    return results


def _extract_len1_gbk(data: bytes):
    """[1B len][GBK bytes] — filter control bytes, replacement chars, min 2 CJK."""
    results = []
    i = 0
    dlen = len(data)
    while i < dlen - 2:
        length = data[i]
        if 2 <= length <= 200:
            end = i + 1 + length
            if end <= dlen:
                raw = data[i+1:end]
                if _has_control_bytes(raw):
                    i += 1
                    continue
                s = _try_decode(raw, 'gbk')
                if s and has_chinese(s) and '\ufffd' not in s:
                    # GBK false positive rất cao — yêu cầu ≥ 2 CJK chars
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s))
                    if cjk_count >= 2:
                        results.append((i, s.strip() or s, raw))
                        i = end
                        continue
        i += 1
    return results


def _extract_len2_gbk(data: bytes):
    """[2B BE len][GBK bytes] — filter control bytes, replacement chars, min 2 CJK."""
    results = []
    i = 0
    dlen = len(data)
    while i < dlen - 3:
        length = struct.unpack_from('>H', data, i)[0]
        if 2 <= length <= 1024:
            end = i + 2 + length
            if end <= dlen:
                raw = data[i+2:end]
                if _has_control_bytes(raw):
                    i += 1
                    continue
                s = _try_decode(raw, 'gbk')
                if s and has_chinese(s) and '\ufffd' not in s:
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s))
                    if cjk_count >= 2:
                        results.append((i, s.strip() or s, raw))
                        i = end
                        continue
        i += 1
    return results


def _extract_null_utf8(data: bytes):
    """Null-terminated UTF-8 strings — filter rác và strings không có CJK."""
    results = []
    start = 0
    dlen = len(data)
    while start < dlen:
        end = data.find(b'\x00', start)
        if end == -1:
            break
        raw = data[start:end]
        seg_len = end - start
        # Phải đủ dài và có CJK bytes
        if seg_len >= 4:
            has_cjk_bytes = bool(_CJK_UTF8_BYTES.search(raw))
            # Vietnamese UTF-8: không có CJK bytes nhưng có multibyte (0xC3-0xE1 range)
            has_viet_bytes = any(0xC0 <= b <= 0xDF for b in raw)
            if (has_cjk_bytes or has_viet_bytes) and not _has_control_bytes(raw):
                s = _try_decode(raw, 'utf-8')
                if s and has_target_language(s) and '\u25a1' not in s and '\ufffd' not in s:
                    s_stripped = s.strip()
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s_stripped))
                    viet_count = len(RE_VIETNAMESE.findall(s_stripped))
                    slen = len(s_stripped)
                    # null-term rất dễ false positive: cần ít nhất 2 CJK hoặc 2 Việt
                    min_cjk = 2 if slen <= 10 else 1
                    if cjk_count >= min_cjk or viet_count >= 2 or (viet_count >= 1 and cjk_count >= 1):
                        results.append((start, s_stripped or s, raw))
        start = end + 1
    return results


def _extract_null_gbk(data: bytes):
    """Null-terminated GBK strings — filter rác và strings không có CJK."""
    results = []
    start = 0
    dlen = len(data)
    while start < dlen:
        end = data.find(b'\x00', start)
        if end == -1:
            break
        raw = data[start:end]
        seg_len = end - start
        if seg_len >= 4:
            if not _has_control_bytes(raw):
                s = _try_decode(raw, 'gbk')
                if s and has_target_language(s) and '\ufffd' not in s:
                    s_stripped = s.strip()
                    cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(s_stripped))
                    # GBK null-term: cần ≥ 2 CJK, không cho 1 CJK lẻ
                    if cjk_count >= 2:
                        results.append((start, s_stripped or s, raw))
        start = end + 1
    return results


def _extract_xse(data: bytes):
    """
    XSE script format: [2B BE length][UTF-8 content][0x00 null terminator]
    Java DataInputStream.readUTF() đọc 2 byte length → đọc đúng số byte đó.
    NULL byte sau content là separator trong XSE bytecode stream.

    Delegate sang _extract_len2_utf8(big_endian=True) để offset/raw trả về
    đúng format — patch_binary() sẽ ghi lại 2-byte length field khi patch.
    """
    return _extract_len2_utf8(data, big_endian=True)


def _extract_utf16(data: bytes, encoding: str):
    """
    Extract strings từ UTF-16 LE hoặc BE data.
    Tách theo null terminator đôi (\\x00\\x00 aligned) hoặc decode toàn bộ rồi split.
    """
    results = []
    # Bỏ BOM nếu có
    start = 0
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        start = 2

    raw_body = data[start:]
    try:
        full_text = raw_body.decode(encoding, errors='replace')
    except Exception:
        return results

    # Split theo các ký tự phân tách phổ biến: null, newline, carriage return
    # Dùng regex để tách đoạn text có nghĩa
    for chunk in re.split(r'[\x00\r\n]+', full_text):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not has_target_language(chunk):
            continue
        if len(chunk) > 500:
            continue
        if any(ord(c) < 0x20 and c not in '\t' for c in chunk):
            continue
        # Tính offset xấp xỉ trong data gốc
        try:
            encoded = chunk.encode(encoding, errors='replace')
            offset = data.find(encoded, start)
            if offset == -1:
                offset = start
        except Exception:
            offset = start
        results.append((offset, chunk, chunk.encode('utf-8', errors='replace')))

    return results


def _extract_xml(data: bytes):
    """
    Extract text từ XML file: text nodes và attribute values có tiếng Trung/Việt.
    Hỗ trợ UTF-8, UTF-16, GBK encoding trong XML.
    Dùng regex thay vì xml.etree để tránh crash khi XML malformed.
    """
    results = []

    # Detect encoding của XML
    encoding = 'utf-8'
    if data[:2] == b'\xff\xfe':
        encoding = 'utf-16-le'
        data = data[2:]
    elif data[:2] == b'\xfe\xff':
        encoding = 'utf-16-be'
        data = data[2:]
    else:
        # Check XML declaration encoding="..."
        head = data[:200]
        m = re.search(rb'encoding=["\']([^"\']+)["\']', head, re.IGNORECASE)
        if m:
            enc_decl = m.group(1).decode('ascii', errors='replace').lower()
            if 'gbk' in enc_decl or 'gb2312' in enc_decl:
                encoding = 'gbk'
            elif 'utf-16' in enc_decl:
                encoding = 'utf-16'

    try:
        text_content = data.decode(encoding, errors='replace')
    except Exception:
        try:
            text_content = data.decode('utf-8', errors='replace')
        except Exception:
            return results

    # Extract text nodes: >content< (giữa tags)
    for m in re.finditer(r'>([^<]{2,500})<', text_content):
        chunk = m.group(1).strip()
        if chunk and has_target_language(chunk):
            raw = chunk.encode('utf-8', errors='replace')
            # offset xấp xỉ theo vị trí trong decoded text (không chính xác tuyệt đối)
            results.append((m.start(1), chunk, raw))

    # Extract attribute values: attr="value" hoặc attr='value'
    for m in re.finditer(r'=["\'"]([^"\']{2,500})["\'""]', text_content):
        chunk = m.group(1).strip()
        if chunk and has_target_language(chunk):
            raw = chunk.encode('utf-8', errors='replace')
            results.append((m.start(1), chunk, raw))

    # Dedup theo text content
    seen = set()
    deduped = []
    for offset, text, raw in results:
        if text not in seen:
            seen.add(text)
            deduped.append((offset, text, raw))

    return deduped


def _extract_with_format(data: bytes, fmt: str):
    """Dispatch to the right extractor. Returns list of (offset, text, raw_bytes)."""
    if fmt == FORMAT_LENGTH1_UTF8:
        return _extract_len1_utf8(data)
    elif fmt == FORMAT_LENGTH2_BE_UTF8:
        return _extract_len2_utf8(data, big_endian=True)
    elif fmt == FORMAT_LENGTH2_LE_UTF8:
        return _extract_len2_utf8(data, big_endian=False)
    elif fmt == FORMAT_LENGTH1_GBK:
        return _extract_len1_gbk(data)
    elif fmt == FORMAT_LENGTH2_BE_GBK:
        return _extract_len2_gbk(data)
    elif fmt == FORMAT_NULL_UTF8:
        return _extract_null_utf8(data)
    elif fmt == FORMAT_NULL_GBK:
        return _extract_null_gbk(data)
    elif fmt == FORMAT_XSE:
        return _extract_xse(data)
    elif fmt == FORMAT_UTF16_LE:
        return _extract_utf16(data, 'utf-16-le')
    elif fmt == FORMAT_UTF16_BE:
        return _extract_utf16(data, 'utf-16-be')
    elif fmt == FORMAT_XML:
        return _extract_xml(data)
    return []


def extract_strings_from_binary(data: bytes, filename: str = ''):
    """
    Main entry point: detect format, extract all Chinese/Vietnamese strings.
    Returns (format_name, list of (offset, text, raw_bytes)).
    """
    fmt = detect_format(data, filename)
    if fmt == FORMAT_UNKNOWN:
        return fmt, []
    entries = _extract_with_format(data, fmt)
    entries = _post_filter_strings(entries)
    return fmt, entries


# ─────────────────────────────────────────────
# Binary Patching
# ─────────────────────────────────────────────

def _encode_for_format(text: str, fmt: str) -> bytes:
    """Encode translated text back to the original format's encoding."""
    if 'gbk' in fmt or 'GBK' in fmt or 'gb2312' in fmt:
        return text.encode('gbk', errors='replace')
    if 'big5' in fmt or 'BIG5' in fmt:
        return text.encode('big5', errors='replace')
    return text.encode('utf-8', errors='replace')


def patch_binary(data: bytes, fmt: str, replacements: dict) -> bytes:
    """
    Patch binary data in-place using (offset → new_text) replacements.
    For length-prefixed formats: rewrites length + content.
    For null-terminated: in-place overwrite padded with nulls (shrinks or pads).
    For raw GBK: direct byte replacement.
    Returns patched bytes.
    """
    if not replacements:
        return data

    # Sort by offset descending so we can splice without offset shifting
    items = sorted(replacements.items(), key=lambda x: x[0], reverse=True)
    buf = bytearray(data)

    for offset, (new_text, orig_raw, _orig_fmt) in items:
        new_raw = _encode_for_format(new_text, fmt)

        if fmt in (FORMAT_LENGTH1_UTF8, FORMAT_LENGTH1_GBK):
            # [1B len][bytes]
            orig_len = len(orig_raw)
            new_len  = len(new_raw)
            if new_len > 255:
                new_raw = new_raw[:255]
                new_len = 255
            chunk = bytes([new_len]) + new_raw
            orig_total = 1 + orig_len
            buf[offset:offset + orig_total] = chunk

        elif fmt in (FORMAT_LENGTH2_BE_UTF8, FORMAT_LENGTH2_BE_GBK):
            orig_len = len(orig_raw)
            new_len  = len(new_raw)
            if new_len > 65535:
                new_raw = new_raw[:65535]
                new_len = 65535
            chunk = struct.pack('>H', new_len) + new_raw
            buf[offset:offset + 2 + orig_len] = chunk

        elif fmt == FORMAT_LENGTH2_LE_UTF8:
            orig_len = len(orig_raw)
            new_len  = len(new_raw)
            if new_len > 65535:
                new_raw = new_raw[:65535]
                new_len = 65535
            chunk = struct.pack('<H', new_len) + new_raw
            buf[offset:offset + 2 + orig_len] = chunk

        elif fmt in (FORMAT_NULL_UTF8, FORMAT_NULL_GBK):
            # Null-terminated: overwrite in-place, pad with nulls if shorter
            orig_len = len(orig_raw)
            new_len  = len(new_raw)
            if new_len <= orig_len:
                buf[offset:offset + orig_len] = new_raw + b'\x00' * (orig_len - new_len)
            else:
                # Can only fit orig_len bytes + null
                buf[offset:offset + orig_len] = new_raw[:orig_len]

    return bytes(buf)


def _post_filter_strings(entries: list) -> list:
    """
    Lọc thêm sau khi extract toàn bộ từ một file.
    Áp dụng các rule contextual (cần nhìn toàn bộ tập strings):
    - Loại bỏ duplicate text (giữ lại offset đầu tiên)
    - Loại bỏ strings trông như resource keys / code tokens
    - Loại bỏ strings trông như số format / template token
    - Kiểm tra thêm tỷ lệ CJK có ý nghĩa
    """
    if not entries:
        return entries

    seen_text: set = set()
    result = []

    # Patterns rác phổ biến trong game J2ME binary
    _RE_RESOURCE_KEY = re.compile(
        r'^[A-Za-z0-9_/\\.\-]+$'            # thuần ASCII path/key
        r'|^\d+[,;\|]\d+'                    # số phân cách bởi dấu
        r'|^[\w\-]+\.(png|jpg|gif|wav|mp3|bin|dat|res)$',  # resource filename
        re.IGNORECASE
    )
    _RE_FORMAT_TOKEN = re.compile(
        r'%\d*[sd]'                          # printf-style format
        r'|\{[0-9a-zA-Z_]+\}'               # {token} template
        r'|\$[A-Z_]+'                        # $VAR style
    )
    # Kiểu "code + 1-2 CJK": ví dụ "OK一", "HP：", "MP："
    _RE_SHORT_CODE_CJK = re.compile(r'^[A-Z]{1,4}[：:＊\*\+\-/\d]*[\u4e00-\u9fff]{1,2}$')

    for offset, text, raw in entries:
        t = text.strip()
        if not t:
            continue

        # Dedup theo text
        if t in seen_text:
            continue

        # Resource key / file path thuần ASCII (đã có CJK ở đây thì is_meaningful đã cho qua)
        if _RE_RESOURCE_KEY.match(t) and not has_chinese(t):
            continue

        # Format tokens không phải text game thực sự
        # Chỉ reject nếu phần CJK rất ít
        if _RE_FORMAT_TOKEN.search(t):
            cjk_in_t = sum(len(m) for m in _CJK_TEXT_RE.findall(t))
            if cjk_in_t < 3:
                continue

        # "CODE＋1-2 CJK": HP：一, MP：二 — kiểu rác rất phổ biến trong game
        if _RE_SHORT_CODE_CJK.match(t):
            continue

        # String quá ngắn mà CJK ít và không phải tiếng Việt thực sự
        cjk_count = sum(len(m) for m in _CJK_TEXT_RE.findall(t))
        viet_count = len(RE_VIETNAMESE.findall(t))
        if len(t) <= 2 and cjk_count < 2 and viet_count < 2:
            continue

        seen_text.add(t)
        result.append((offset, t, raw))

    return result


# ─────────────────────────────────────────────
# JAR / ZIP Scanner
# ─────────────────────────────────────────────

def scan_jar(jar_path: str, progress_cb=None):
    """
    Scan JAR/ZIP: chỉ xử lý files trong ALLOWED_EXTENSIONS,
    filter binary magic, dedup theo (jar_entry, offset, fmt).
    """
    results = []
    seen_keys: set = set()

    with zipfile.ZipFile(jar_path, 'r') as zf:
        all_entries = zf.namelist()

        # Lọc: bỏ directories, .class, META-INF
        # Chỉ scan extensions có khả năng chứa strings (allowlist + no-ext)
        _EXT_BLACKLIST = {
            '.class', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
            '.mp3', '.ogg', '.wav', '.mid', '.aac', '.jar', '.zip',
            '.gz', '.bz2', '.mf', '.sf', '.rsa', '.dsa',
            # Binary game data không chứa strings text
            '.map', '.palet', '.palette', '.pal', '.fnt', '.font',
            '.tileset', '.tile', '.spr', '.sprite', '.anim',
            '.idx', '.index', '.lut', '.raw',
        }

        # Extensions rõ ràng có strings
        _EXT_ALLOWLIST = {
            '.bin', '.dat', '.res', '.pak', '.txt', '.ini', '.cfg',
            '.xse', '.xs', '.scr', '.tbl', '.db', '.msg', '.arc',
            '.xml', '.json', '.csv', '.lang', '.lng', '.str', '.string',
            '.prop', '.properties', '.conf', '.config',
        }

        def _should_scan(name: str) -> bool:
            if name.endswith('/'):
                return False
            if name.startswith('META-INF/'):
                return False
            ext = os.path.splitext(name)[1].lower()
            # Blacklist tuyệt đối
            if ext in _EXT_BLACKLIST:
                return False
            # No extension → scan (nhiều game J2ME dùng file không có ext)
            if not ext:
                return True
            # Allowlist → scan
            if ext in _EXT_ALLOWLIST:
                return True
            # Extension lạ không biết → dùng is_structured_binary để quyết định
            # (sẽ check magic bytes và CJK content)
            return True

        entries = [n for n in all_entries if _should_scan(n)]
        total = len(entries)

        for i, name in enumerate(entries):
            if progress_cb:
                progress_cb(i + 1, total, name)
            try:
                data = zf.read(name)
                basename = os.path.basename(name)
                if not is_structured_binary(data, basename):
                    continue
                fmt, string_entries = extract_strings_from_binary(data, basename)
                if not string_entries:
                    continue
                for offset, text, raw in string_entries:
                    # Lọc strings rác trước khi thêm vào kết quả
                    if not _is_meaningful_string(text):
                        continue
                    key = (name, offset, fmt)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    results.append({
                        'jar_entry':  name,
                        'offset':     offset,
                        'raw':        raw,
                        'fmt':        fmt,
                        'original':   text,
                        'translated': text,
                        'enabled':    True,
                    })
            except Exception:
                continue
    return results


def patch_jar(jar_path: str, out_path: str, string_list: list, progress_cb=None):
    # Group replacements by jar entry
    entry_replacements = {}  # jar_entry → {offset: (new_text, orig_raw, fmt)}
    for item in string_list:
        if not item['enabled']:
            continue
        if item['translated'] == item['original']:
            continue
        ent = item['jar_entry']
        if ent not in entry_replacements:
            entry_replacements[ent] = {}
        entry_replacements[ent][item['offset']] = (
            item['translated'], item['raw'], item['fmt']
        )

    with zipfile.ZipFile(jar_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            names = zin.namelist()
            total = len(names)
            for i, name in enumerate(names):
                if progress_cb:
                    progress_cb(i + 1, total, name)
                data = zin.read(name)
                if name in entry_replacements:
                    # Determine format from first item
                    first_item = next(iter(entry_replacements[name].values()))
                    fmt = first_item[2]
                    try:
                        data = patch_binary(data, fmt, entry_replacements[name])
                    except Exception as e:
                        print(f"Patch error {name}: {e}")
                zout.writestr(zipfile.ZipInfo(name), data)


# ─────────────────────────────────────────────
# Translation
# ─────────────────────────────────────────────

_translate_cache = {}
_google_translator = None

def get_translator():
    global _google_translator
    if not TRANSLATOR_OK:
        return None
    if _google_translator is None:
        _google_translator = GoogleTranslator(source='zh-CN', target='vi')
    return _google_translator


def translate_batch(items: list, indices: list, accent: bool, progress_cb=None, stop_flag=None):
    tr = get_translator()
    if tr is None:
        return
    total = len(indices)
    for n, idx in enumerate(indices):
        if stop_flag and stop_flag():
            break
        item = items[idx]
        src_text = item['original']

        if not has_chinese(src_text):
            if progress_cb:
                progress_cb(n + 1, total)
            continue

        try:
            if src_text in _translate_cache:
                vi = _translate_cache[src_text]
            else:
                vi = tr.translate(src_text)
                _translate_cache[src_text] = vi

            if vi is None or not vi.strip():
                if progress_cb:
                    progress_cb(n + 1, total)
                continue

            if not accent and UNIDECODE_OK:
                vi = unidecode(vi)

            item['translated'] = vi
        except Exception:
            pass

        if progress_cb:
            progress_cb(n + 1, total)
        time.sleep(0.01)


# ─────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────

PAGE_SIZE = 200


_RE_CJK_CHAR = re.compile(r'[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff\u2e80-\u2eff\u31c0-\u31ef]')

def _redecode_raw(raw: bytes, new_fmt: str) -> str | None:
    """
    Decode lại raw bytes của 1 entry theo encoding mới.
    raw = field content bytes (không kèm length prefix).

    Validation:
    - UTF-8 result phải có ít nhất 1 CJK char (tránh GBK bytes tình cờ valid UTF-8)
    - GBK/BIG5 result không được có replacement char \ufffd
    - Result phải printable (không có control bytes)
    """
    if not raw:
        return None
    enc_map = {
        'len1_utf8':    'utf-8',
        'len2be_utf8':  'utf-8',
        'len2le_utf8':  'utf-8',
        'null_utf8':    'utf-8',
        'len1_gbk':     'gbk',
        'len2be_gbk':   'gbk',
        'null_gbk':     'gbk',
        'len1_big5':    'big5',
        'len1_gb2312':  'gb2312',
        'xse':          'utf-8',
    }
    enc = enc_map.get(new_fmt)
    if not enc:
        return None

    is_utf8 = (enc == 'utf-8')

    try:
        text = raw.decode(enc, errors='strict')
    except UnicodeDecodeError:
        try:
            text = raw.decode(enc, errors='replace')
        except Exception:
            return None

    if not text or not text.strip():
        return None

    # Reject nếu có replacement char hoặc control bytes
    if chr(0xfffd) in text:
        return None
    if any(ord(c) < 0x20 and c not in '\r\n\t' for c in text):
        return None

    # UTF-8: phải có ít nhất 1 CJK char
    # (tránh GBK/Latin1 bytes tình cờ decode được thành UTF-8 Armenian/IPA/etc)
    if is_utf8 and not _RE_CJK_CHAR.search(text):
        return None

    return text


def translate_single(src_text: str, accent: bool) -> str:
    """Dịch một string đơn, trả về string đã dịch hoặc src_text nếu lỗi."""
    if not has_chinese(src_text):
        return src_text
    try:
        if src_text in _translate_cache:
            vi = _translate_cache[src_text]
        else:
            tr = get_translator()
            if tr is None:
                return src_text
            vi = tr.translate(src_text)
            if vi:
                _translate_cache[src_text] = vi
        if not vi or not vi.strip():
            return src_text
        if not accent and UNIDECODE_OK:
            vi = unidecode(vi)
        return vi
    except Exception:
        return src_text

# Engine only — no tkinter GUI
