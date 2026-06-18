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

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import zipfile
import struct
import os
import re
import time
from io import BytesIO
from collections import Counter

try:
    import requests
    TRANSLATOR_OK = True
except ImportError:
    TRANSLATOR_OK = False

try:
    from unidecode import unidecode
    UNIDECODE_OK = True
except ImportError:
    UNIDECODE_OK = False

# ── Gemini API config ──
GEMINI_API_KEY          = "AIzaSyCSJyDQ0eIudCv8VtmK9qM4y4JeY8o4dfY"
GEMINI_MODEL_PRIMARY    = "gemini-3.1-flash-lite"  # nhanh nhat, thinking toi thieu theo mac dinh
GEMINI_MODEL_SECONDARY  = "gemini-3.5-flash"       # chat luong cao hon, dung khi lite loi
GEMINI_MODEL_FALLBACK   = "gemini-2.5-flash"       # fallback the he cu, dung khi ca 2 model Gemini 3 deu loi/qua tai

def _gemini_url(model: str) -> str:
    return (f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={GEMINI_API_KEY}")

def _thinking_config_for(model: str) -> dict:
    """
    Gemini 3.x dùng `thinkingLevel`, Gemini 2.5.x dùng `thinkingBudget`.
    Đặt mức thấp nhất để giảm token bị "suy luận ngầm" ăn mất, tránh cắt cụt
    câu trả lời thật và giảm thời gian dịch.
    """
    if model.startswith("gemini-3"):
        return {"thinkingLevel": "low"}
    return {"thinkingBudget": 0}


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

    # Skip theo magic bytes THẬT (image/audio/zip/exe) — KHÔNG skip UTF-16 BOM
    # Đây là check theo NỘI DUNG file, không theo đuôi tên file, vì nhiều game
    # giả đuôi file để né scan hoặc do engine đặt tên tùy ý. Đây là tiêu chí
    # loại trừ DUY NHẤT theo "đã biết chắc là định dạng khác" — không còn bất
    # kỳ blacklist theo TÊN FILE/extension nào nữa, để scan được mọi file
    # binary thật, kể cả khi đặt đuôi giả.
    for magic in BINARY_MAGICS:
        if data.startswith(magic):
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
FORMAT_QUOTED_INPLACE   = 'quoted_inplace'  # text trong "..." của code script (showDlg(...,"text"))
                                              # — patch in-place, KHÔNG ghi length-prefix/null nào cả,
                                              # để không bao giờ đụng vào code xung quanh dấu nháy.
FORMAT_SCRIPT_TEXT      = 'script_text'     # File LÀ SOURCE CODE SCRIPT plaintext (nhiều dòng dạng
                                              # lệnh(tham_số,"text")), KHÔNG phải binary length-prefix.
                                              # Quét toàn file bằng regex tìm "..." chứa CJK/Việt,
                                              # patch in-place — không bao giờ brute-force length-prefix
                                              # trên dữ liệu này (dễ bắt nhầm/nuốt code xung quanh).

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
    FORMAT_QUOTED_INPLACE:  'Quoted text in script code',
    FORMAT_SCRIPT_TEXT:     'Script source (quoted strings)',
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

    # ── Step 0.5: Plaintext script source (ƯU TIÊN CAO NHẤT) ──
    # Phải check TRƯỚC cả .xse/.xs, vì nhiều file .xse/.xs/.dat/.bin thực ra
    # là SOURCE CODE SCRIPT dạng text (lệnh(tham_số,"text")), không phải
    # binary length-prefix. Nếu để brute-force len1/len2 chạy trên dữ liệu
    # này, length field "giả" trùng khớp ngẫu nhiên sẽ nuốt nguyên cụm code
    # (tên hàm, số tham số, dấu ngoặc) lẫn vào text → patch lại phá cú pháp
    # script → crash game. Phải route sang FORMAT_SCRIPT_TEXT (quét theo
    # regex "..." trên toàn file) trước khi thử bất kỳ format binary khác.
    if _is_plaintext_script(data):
        return FORMAT_SCRIPT_TEXT

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
    """
    Decode Java Modified UTF-8 (giống DataInputStream.readUTF() xử lý nội
    dung sau khi đã đọc 2-byte length). Java MUTF-8 khác UTF-8 chuẩn ở 2 điểm:
      1. U+0000 luôn encode thành 2 byte 0xC0 0x80 (không phải 1 byte 0x00).
      2. Code point ngoài BMP (> U+FFFF, ví dụ emoji) được encode thành
         MỘT CẶP surrogate UTF-16 (high + low), MỖI surrogate lại encode
         riêng theo dạng 3-byte (0xED ...), tổng cộng 6 byte — KHÔNG dùng
         4-byte sequence như UTF-8 chuẩn.
    Decoder này phải hiểu được dạng "surrogate pair 3+3 byte" đó, nếu không
    sẽ tạo ra 2 ký tự surrogate rời (lone surrogates) gây lỗi khi ghi lại.
    """
    try:
        out = []
        i = 0
        n = len(raw)

        while i < n:
            b = raw[i]

            if b == 0:
                # Byte 0x00 đơn lẻ không hợp lệ trong MUTF-8 (NUL phải là
                # 0xC0 0x80) — đây là dữ liệu hỏng/không phải MUTF-8 thật.
                return None

            if b < 0x80:
                out.append(chr(b))
                i += 1

            elif (b & 0xE0) == 0xC0:
                if i + 1 >= n:
                    return None

                b2 = raw[i + 1]
                if (b2 & 0xC0) != 0x80:
                    return None

                code = ((b & 0x1F) << 6) | (b2 & 0x3F)
                out.append(chr(code))
                i += 2

            elif (b & 0xF0) == 0xE0:
                if i + 2 >= n:
                    return None

                b2 = raw[i + 1]
                b3 = raw[i + 2]
                if (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80:
                    return None

                code = (
                    ((b & 0x0F) << 12)
                    | ((b2 & 0x3F) << 6)
                    | (b3 & 0x3F)
                )
                # 0xD800-0xDFFF = surrogate halves. Java MUTF-8 mã hoá 1 ký
                # tự ngoài BMP thành 2 surrogate liên tiếp (6 byte). chr()
                # với 1 surrogate đơn sẽ tạo lone surrogate hợp lệ trong
                # Python str — ta giữ nguyên, rồi ghép lại bằng surrogatepass
                # khi cần, nhưng để hiển thị/dịch, Python tự ghép cặp khi 2
                # surrogate liền nhau xuất hiện trong chuỗi UTF-16 logic.
                out.append(chr(code))
                i += 3

            else:
                return None

        # Ghép các cặp surrogate (high 0xD800-0xDBFF theo sau bởi low
        # 0xDC00-0xDFFF) thành 1 code point thật, để chuỗi Python sạch và
        # encode_mutf8() có thể tách lại đúng y hệt khi ghi ngược.
        merged = []
        j = 0
        L = len(out)
        while j < L:
            c = out[j]
            cp = ord(c)
            if 0xD800 <= cp <= 0xDBFF and j + 1 < L:
                cp2 = ord(out[j + 1])
                if 0xDC00 <= cp2 <= 0xDFFF:
                    combined = 0x10000 + ((cp - 0xD800) << 10) + (cp2 - 0xDC00)
                    merged.append(chr(combined))
                    j += 2
                    continue
            merged.append(c)
            j += 1

        s = ''.join(merged)
        return s if s.strip() else None

    except Exception:
        return None


def encode_mutf8(text: str) -> bytes:
    """
    Encode 1 chuỗi Python str thành Java Modified UTF-8 — mô phỏng ĐÚNG
    behavior của java.io.DataOutputStream.writeUTF() (phần nội dung, KHÔNG
    gồm 2-byte length, hàm gọi bên ngoài tự ghép length prefix).

    Quy tắc MUTF-8 (theo JVM spec, class file format §4.4.7):
      - U+0000              → 2 byte: 0xC0 0x80   (KHÔNG bao giờ ghi 1 byte 0x00)
      - U+0001..U+007F      → 1 byte: 0xxxxxxx
      - U+0080..U+07FF      → 2 byte: 110xxxxx 10xxxxxx
      - U+0800..U+FFFF      → 3 byte: 1110xxxx 10xxxxxx 10xxxxxx
      - > U+FFFF (ngoài BMP)→ encode thành surrogate pair UTF-16 (high, low),
                              MỖI surrogate lại encode riêng theo dạng 3-byte
                              ở trên → tổng 6 byte. (KHÁC UTF-8 chuẩn dùng
                              4 byte cho trường hợp này.)
    """
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp == 0:
            out += bytes([0xC0, 0x80])
        elif cp <= 0x7F:
            out.append(cp)
        elif cp <= 0x7FF:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
        elif cp <= 0xFFFF:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
        else:
            # Ngoài BMP: tách thành surrogate pair UTF-16 rồi encode mỗi
            # surrogate theo dạng 3-byte (giống writeUTF của Java thật).
            cp -= 0x10000
            hi = 0xD800 + (cp >> 10)
            lo = 0xDC00 + (cp & 0x3FF)
            for half in (hi, lo):
                out.append(0xE0 | (half >> 12))
                out.append(0x80 | ((half >> 6) & 0x3F))
                out.append(0x80 | (half & 0x3F))
    return bytes(out)


def mutf8_byte_length(text: str) -> int:
    """Tính số byte MUTF-8 sẽ chiếm, KHÔNG gồm 2-byte length prefix."""
    return len(encode_mutf8(text))


def safe_truncate_mutf8(text: str, max_bytes: int) -> str:
    """
    Cắt chuỗi để encode_mutf8(result) có độ dài byte <= max_bytes, CẮT THEO
    KÝ TỰ HOÀN CHỈNH (không bao giờ cắt giữa 1 sequence nhiều byte), để
    không bao giờ tạo ra MUTF-8 hỏng (lead byte không có continuation byte).
    """
    if max_bytes <= 0:
        return ''
    out_chars = []
    total = 0
    for ch in text:
        # Mỗi ký tự ngoài BMP chiếm 6 byte (2 surrogate x 3 byte), còn lại
        # encode_mutf8 trên 1 ký tự cho đúng độ dài byte của riêng nó.
        ch_bytes = len(encode_mutf8(ch))
        if total + ch_bytes > max_bytes:
            break
        out_chars.append(ch)
        total += ch_bytes
    return ''.join(out_chars)

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


def _is_plaintext_script(data: bytes) -> bool:
    """
    Phát hiện file LÀ SOURCE CODE SCRIPT plaintext (dạng JS/Lua/DSL game),
    ví dụ:
        showDlg(1,0,"好,我一定会去的")
        showDlg(2,0,"我们一言为定,...")
    KHÔNG phải binary length-prefix nhị phân. Đặc trưng nhận diện:
      1. Gần như toàn bộ byte là ASCII printable + whitespace + CJK UTF-8
         hợp lệ (rất ít/không có byte binary noise thật — khác hẳn binary
         length-prefix nơi length field là byte số nhị phân ngẫu nhiên).
      2. Có pattern identifier ASCII theo sau bởi '(' xuất hiện NHIỀU LẦN
         (đặc trưng lệnh gọi hàm script, không phải dữ liệu).
      3. Có ít nhất vài cặp dấu nháy kép "..." chứa CJK/Việt.

    Khi True: bắt buộc dùng FORMAT_SCRIPT_TEXT (quét theo regex "..." trên
    toàn file), KHÔNG để brute-force length-prefix (len1/len2 utf8/gbk)
    chạy trên dữ liệu này — vì length field "giả" trùng khớp ngẫu nhiên rất
    dễ nuốt nguyên cụm code (tên hàm, số tham số, dấu ngoặc) lẫn vào text,
    patch lại sẽ phá vỡ cú pháp script và làm crash game.
    """
    sample = data[:8192]
    if len(sample) < 8:
        return False

    # Tỷ lệ byte "an toàn": ASCII printable, tab/newline/CR, hoặc CJK UTF-8 hợp lệ
    safe = 0
    i = 0
    n = len(sample)
    while i < n:
        b = sample[i]
        if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E:
            safe += 1
            i += 1
            continue
        if 0xE4 <= b <= 0xE9 and i + 2 < n:
            b2, b3 = sample[i+1], sample[i+2]
            if 0x80 <= b2 <= 0xBF and 0x80 <= b3 <= 0xBF:
                safe += 3
                i += 3
                continue
        i += 1
    safe_ratio = safe / n
    if safe_ratio < 0.90:
        return False  # quá nhiều byte binary noise → không phải plaintext script

    # Đếm số lần xuất hiện pattern "identifier(" — đặc trưng lệnh gọi hàm script
    call_pattern = re.compile(rb'[A-Za-z_][A-Za-z0-9_]{1,30}\s*\(')
    n_calls = len(call_pattern.findall(sample))

    # Đếm số cặp dấu nháy "..." có chứa CJK UTF-8 bên trong
    quoted_cjk = re.compile(rb'"[^"]{0,300}"')
    quote_hits = 0
    for m in quoted_cjk.finditer(sample):
        if _CJK_UTF8_BYTES.search(m.group(0)):
            quote_hits += 1

    return n_calls >= 3 and quote_hits >= 2


def _extract_script_text(data: bytes):
    """
    Extract text trong dấu nháy kép "..." từ file LÀ source code script
    plaintext. Quét toàn file bằng regex, không brute-force length-prefix.
    Trả về list (offset, text, raw) — offset là vị trí byte thật trong data
    của phần text bên trong dấu nháy (không gồm dấu nháy), để patch in-place
    đúng chỗ mà không đụng code xung quanh.
    """
    results = []
    # Hỗ trợ cả " " và “ ” (smart quotes) và 「」(CJK quotes) phòng trường hợp
    quoted_re = re.compile(rb'"([^"]{1,500})"')
    for m in quoted_re.finditer(data):
        raw = m.group(1)
        if not _CJK_UTF8_BYTES.search(raw) and not any(0xC0 <= b <= 0xDF for b in raw):
            continue
        try:
            s = raw.decode('utf-8')
        except Exception:
            continue
        if not has_target_language(s):
            continue
        if '\ufffd' in s:
            continue
        offset = m.start(1)
        results.append((offset, s.strip() or s, raw))
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
    elif fmt == FORMAT_SCRIPT_TEXT:
        return _extract_script_text(data)
    return []


def extract_strings_from_binary(data: bytes, filename: str = ''):
    """
    Main entry point: detect format, extract all Chinese/Vietnamese strings.
    Returns (format_name, list of (offset, text, raw_bytes, entry_fmt)).

    entry_fmt thường == format_name (toàn file dùng 1 format), NHƯNG với các
    entry bị "unwrap" từ một dòng code script bị nuốt nguyên khối (ví dụ
    showDlg(1,0,"text") bắt nhầm thành 1 string null-terminated), hoặc khi
    base format là FORMAT_SCRIPT_TEXT (toàn file là plaintext script),
    entry_fmt sẽ là FORMAT_QUOTED_INPLACE — patch_binary() ghi đè in-place,
    không bao giờ thêm/sửa length-prefix hay null-terminator đè lên code.
    """
    fmt = detect_format(data, filename)
    if fmt == FORMAT_UNKNOWN:
        return fmt, []
    entries = _extract_with_format(data, fmt)
    # FORMAT_SCRIPT_TEXT: mọi entry đã là (offset, text trong nháy, raw) —
    # patch phải in-place giống FORMAT_QUOTED_INPLACE, không có length-prefix.
    base_fmt_for_filter = FORMAT_QUOTED_INPLACE if fmt == FORMAT_SCRIPT_TEXT else fmt
    entries = _post_filter_strings(entries, base_fmt=base_fmt_for_filter)
    return fmt, entries


# ─────────────────────────────────────────────
# Binary Patching
# ─────────────────────────────────────────────

def _encode_for_format(text: str, fmt: str) -> bytes:
    """
    Encode translated text back to the original format's encoding.

    QUAN TRỌNG: FORMAT_LENGTH2_BE_UTF8 (= 'len2be_utf8') là Java
    DataOutputStream.writeUTF() / DataInputStream.readUTF() — encoding ở
    đây PHẢI là Modified UTF-8 (MUTF-8), KHÔNG được dùng text.encode('utf-8')
    thông thường. UTF-8 chuẩn và MUTF-8 khác nhau ở cách encode U+0000 và
    các code point ngoài BMP (xem encode_mutf8()), nên dùng nhầm UTF-8 có
    thể tạo ra byte sequence mà readUTF() coi là hỏng → UTFDataFormatException.
    """
    if fmt == FORMAT_LENGTH2_BE_UTF8:
        return encode_mutf8(text)
    if 'gbk' in fmt or 'GBK' in fmt or 'gb2312' in fmt:
        return text.encode('gbk', errors='replace')
    if 'big5' in fmt or 'BIG5' in fmt:
        return text.encode('big5', errors='replace')
    return text.encode('utf-8', errors='replace')


def patch_binary(data: bytes, fmt: str, replacements: dict) -> bytes:
    """
    Patch binary data in-place using (offset → new_text) replacements.

    NGUYÊN TẮC BẮT BUỘC (đã sửa lại hoàn toàn so với bản cũ):

    1) Length prefix LUÔN khớp đúng số byte thật của content được ghi.
       Bản cũ giữ "tổng kích thước slot" cố định bằng orig_len rồi đệm
       \\x00 vào CUỐI content khi bản dịch ngắn hơn gốc. Điều này SAI với
       format kiểu DataInputStream.readUTF(): length field nói "đọc N byte"
       nhưng N = new_len (đúng), còn (orig_len - new_len) byte \\x00 dư ra
       lại nằm NGAY SAU phần content trong slot cũ — readUTF() chỉ đọc đúng
       N byte rồi dừng, nên N byte \\x00 dư đó KHÔNG bị bỏ qua mà trở thành
       phần ĐẦU của field kế tiếp trong stream (vì các file .s này là nhiều
       writeUTF() ghi liên tiếp không có padding giữa các field) → field
       sau bị lệch/hỏng, dẫn thẳng tới UTFDataFormatException ở field đó
       hoặc field xa hơn. Vì vậy ở đây ta KHÔNG giữ slot cố định: length
       prefix = đúng len(new_raw), buffer file co/giãn theo đúng chênh lệch
       thật, không có byte rác nào bị chèn thêm vào content.

    2) Vì buffer co giãn, các offset của entry KHÁC trong CÙNG file sẽ bị
       lệch nếu xử lý từ đầu file xuống cuối. Để offset luôn đúng mà không
       cần tính lại, ta xử lý theo thứ tự offset GIẢM DẦN (cuối file trước)
       — mọi entry chưa xử lý luôn có offset nhỏ hơn offset đang patch, nên
       việc buffer dài/ngắn ra ở vị trí sau không ảnh hưởng gì tới offset
       (chưa dùng) ở phía trước. Đây là lý do bắt buộc phải sort giảm dần,
       khác với ghi chú "không cần" ở bản cũ.

    3) Không bao giờ cắt (truncate) raw bytes giữa 1 ký tự multi-byte. Nếu
       cần giới hạn độ dài (ví dụ length field tối đa 1 byte / 2 byte theo
       chuẩn unsigned), cắt theo KÝ TỰ HOÀN CHỈNH bằng safe_truncate_mutf8()
       / safe_truncate_utf8(), không bao giờ bytes[:n] thô.

    Returns patched bytes.
    """
    if not replacements:
        return data

    # Offset GIẢM DẦN là bắt buộc (không chỉ là "an toàn thêm"): vì content
    # region giờ có thể dài/ngắn hơn gốc, splice ở offset lớn không còn ảnh
    # hưởng byte ở offset nhỏ hơn (chưa xử lý) — ngược lại nếu đi tăng dần
    # sẽ làm lệch toàn bộ offset còn lại.
    items = sorted(replacements.items(), key=lambda x: x[0], reverse=True)
    buf = bytearray(data)

    for offset, (new_text, orig_raw, _orig_fmt) in items:
        new_raw = _encode_for_format(new_text, fmt)

        if fmt in (FORMAT_LENGTH1_UTF8, FORMAT_LENGTH1_GBK):
            # [1B len][bytes] — length field unsigned 1 byte, tối đa 255.
            # Length MỚI = đúng len(new_raw); nếu vượt 255 phải cắt theo
            # ký tự hoàn chỉnh (không cắt giữa multi-byte sequence) cho tới
            # khi vừa khít, KHÔNG đệm \\x00 khi ngắn hơn — slot co/giãn theo
            # đúng nội dung thật.
            if len(new_raw) > 255:
                is_gbk = fmt == FORMAT_LENGTH1_GBK
                new_text2 = new_text
                while len(new_raw) > 255 and new_text2:
                    new_text2 = new_text2[:-1]
                    new_raw = _encode_for_format(new_text2, fmt)
                if len(new_raw) > 255:
                    new_raw = new_raw[:255]  # fallback cùng cực, không còn ký tự để cắt
            orig_len = len(orig_raw)
            new_len = len(new_raw)
            chunk = bytes([new_len]) + new_raw
            buf[offset:offset + 1 + orig_len] = chunk

        elif fmt in (FORMAT_LENGTH2_BE_UTF8, FORMAT_LENGTH2_BE_GBK):
            # [2B BE len][bytes] — đây chính là định dạng Java
            # DataOutputStream.writeUTF() / readUTF(). Length field unsigned
            # 2 byte BE, tối đa 65535 — KHÔNG bao giờ vượt trong thực tế.
            # Length MỚI = đúng len(new_raw) (đã encode MUTF-8 thật ở
            # _encode_for_format), KHÔNG đệm \\x00 vào content.
            if len(new_raw) > 65535:
                if fmt == FORMAT_LENGTH2_BE_UTF8:
                    new_text = safe_truncate_mutf8(new_text, 65535)
                    new_raw = encode_mutf8(new_text)
                else:
                    while len(new_raw) > 65535 and new_text:
                        new_text = new_text[:-1]
                        new_raw = _encode_for_format(new_text, fmt)
            orig_len = len(orig_raw)
            new_len = len(new_raw)
            chunk = struct.pack('>H', new_len) + new_raw
            buf[offset:offset + 2 + orig_len] = chunk

        elif fmt == FORMAT_LENGTH2_LE_UTF8:
            # [2B LE len][bytes] — tương tự len2be nhưng little-endian.
            if len(new_raw) > 65535:
                while len(new_raw) > 65535 and new_text:
                    new_text = new_text[:-1]
                    new_raw = _encode_for_format(new_text, fmt)
            orig_len = len(orig_raw)
            new_len = len(new_raw)
            chunk = struct.pack('<H', new_len) + new_raw
            buf[offset:offset + 2 + orig_len] = chunk

        elif fmt in (FORMAT_NULL_UTF8, FORMAT_NULL_GBK):
            # Null-terminated: KHÔNG có length prefix để cập nhật, ranh
            # giới field là chính byte \\x00 — nên ở đây slot ĐƯỢC PHÉP
            # co/giãn tự do (giống FORMAT_QUOTED_INPLACE) mà không phá field
            # sau, vì ta luôn ghi đúng 1 byte \\x00 ở cuối làm terminator
            # MỚI, không đệm thêm \\x00 thừa vào giữa content.
            orig_len = len(orig_raw)
            buf[offset:offset + orig_len + 1] = new_raw + b'\x00'

        elif fmt == FORMAT_QUOTED_INPLACE:
            # Text nằm TRONG dấu nháy kép của một dòng code script
            # (ví dụ showDlg(1,0,"text")). KHÔNG có length-prefix, KHÔNG có
            # null-terminator riêng — đây CHÍNH XÁC là phần bytes giữa hai
            # dấu " trong file gốc. Ghi đè ĐÚNG offset, ĐÚNG độ dài orig_raw,
            # TUYỆT ĐỐI không chèn thêm byte nào (không length field, không
            # \x00) để không bao giờ làm lệch các byte code xung quanh
            # (showDlg(, số tham số, dấu ngoặc đóng, ký tự xuống dòng...).
            #
            # Nếu new_raw dài hơn orig_raw: vẫn ghi đủ new_raw — vùng dữ liệu
            # sẽ giãn ra đúng bằng phần chênh lệch, các byte code phía SAU
            # (dấu ngoặc đóng, dấu phẩy kế tiếp...) sẽ tự dịch theo, không bị
            # mất hay đè — vì đây là buffer mutable, splice tự nối liền mạch.
            # Nếu ngắn hơn: buffer co lại tương ứng, code phía sau dịch về
            # gần hơn — vẫn nguyên vẹn cú pháp, không có byte rác chèn vào.
            orig_len = len(orig_raw)
            buf[offset:offset + orig_len] = new_raw

    return bytes(buf)


def _unwrap_script_code_entry(offset: int, text: str, raw: bytes):
    """
    Phát hiện entry trông như DÒNG MÃ SCRIPT bị nuốt nguyên cả khối, ví dụ:
        showDlg(1,0,"好,我一定会去的")
        showDlg(2,0,"我们一言为定,那铃儿先告辞了,公子可要来啊")
    Đây xảy ra khi extractor (đặc biệt null_utf8/null_gbk fallback) không có
    ranh giới rõ ràng (không \\x00 giữa các dòng) nên nuốt luôn cả tên hàm,
    dấu ngoặc, số tham số lẫn dấu nháy vào một "string". Nếu patch nguyên
    văn entry này, bản dịch sẽ ghi đè luôn cả `showDlg(1,0,` → hỏng cú pháp
    script → crash game.

    Heuristic nhận diện "đây là code, không phải text thuần":
      - Có pattern tên_hàm ASCII theo sau bởi '(' ngay trước phần có CJK/Việt
      - HOẶC có >= 2 cặp dấu ngoặc kép "..." trong cùng entry (nhiều lời thoại
        dính liền — dấu hiệu nuốt nhiều dòng script)
      - HOẶC bắt đầu bằng identifier ASCII + '(' + số/dấu phẩy trước khi gặp CJK

    Nếu khớp: trả về list các (offset_mới, text_mới, raw_mới) — MỖI cặp dấu
    nháy chứa CJK/Việt trở thành 1 entry riêng, offset được tính lại đúng vị
    trí byte thật trong `raw` gốc (offset_mới = offset + vị trí bắt đầu nội
    dung trong dấu nháy), để patch_binary() ghi đúng chỗ, không đụng vào
    phần code xung quanh.

    Nếu KHÔNG khớp pattern code: trả về None (giữ nguyên xử lý như cũ).
    """
    # Dấu hiệu rõ nhất: tên hàm/identifier ASCII ngay trước '(' ở đầu hoặc giữa entry,
    # và có ít nhất một cặp dấu nháy kép bao quanh phần CJK/Việt.
    _RE_CODE_CALL = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\s*\([^()"]{0,40}["\u201c]')
    _RE_QUOTED = re.compile(r'["\u201c\u300c]([^"\u201d\u300d]{1,300})["\u201d\u300d]')

    looks_like_code = bool(_RE_CODE_CALL.search(text))
    quote_matches = list(_RE_QUOTED.finditer(text))

    # Nếu không có dấu hiệu code VÀ chỉ <=1 cụm trong dấu nháy → không phải case này
    if not looks_like_code and len(quote_matches) <= 1:
        return None
    # Cần ít nhất 1 cụm trong dấu nháy để tách ra
    if not quote_matches:
        return None

    new_entries = []
    for m in quote_matches:
        inner = m.group(1).strip()
        if not inner:
            continue
        if not has_target_language(inner):
            continue  # cụm trong nháy không có CJK/Việt → bỏ (vd tham số chuỗi khác)

        # Tính offset byte thật: encode phần text TRƯỚC vị trí match để biết
        # số byte lệch trong raw gốc (vì text là str đã decode, raw là bytes).
        prefix_str = text[:m.start(1)]
        try:
            # Encode prefix theo cùng encoding đã dùng để decode raw ban đầu.
            # Ta không biết chắc encoding gốc ở đây, nhưng vì offset chỉ cần
            # đúng tới byte UTF-8 (đa số pipeline dùng UTF-8/MUTF-8), thử UTF-8
            # trước; nếu raw là GBK thì độ lệch theo ký tự vẫn xấp xỉ đúng vì
            # ASCII (tên hàm, số, dấu ngoặc) luôn 1 byte = 1 ký tự trong cả 2 encoding.
            prefix_bytes_len = len(prefix_str.encode('utf-8'))
        except Exception:
            prefix_bytes_len = len(prefix_str)

        new_offset = offset + prefix_bytes_len
        new_raw = inner.encode('utf-8', errors='replace')
        new_entries.append((new_offset, inner, new_raw))

    return new_entries if new_entries else None


def _unwrap_script_code_entry(offset: int, text: str, raw: bytes, base_fmt: str):
    """
    Phát hiện entry trông như DÒNG MÃ SCRIPT bị nuốt nguyên cả khối, ví dụ:
        showDlg(1,0,"好,我一定会去的")
        showDlg(2,0,"我们一言为定,那铃儿先告辞了,公子可要来啊")
    Đây xảy ra khi extractor (đặc biệt null_utf8/null_gbk fallback, hoặc
    len2be_utf8 khi 2-byte length tình cờ trùng khớp một đoạn dài) không có
    ranh giới rõ ràng nên nuốt luôn cả tên hàm, dấu ngoặc, số tham số lẫn
    dấu nháy vào một "string". Nếu patch nguyên văn entry này theo base_fmt
    (length-prefixed hoặc null-terminated), bản dịch sẽ ghi đè luôn lên
    `showDlg(1,0,` hoặc thêm 2-byte length giả vào giữa code → hỏng cú
    pháp script → crash game.

    Heuristic nhận diện "đây là code, không phải text thuần":
      - Có pattern tên_hàm ASCII theo sau bởi '(' ngay trước phần có CJK/Việt
      - HOẶC có >= 2 cặp dấu ngoặc kép "..." trong cùng entry (nhiều lời thoại
        dính liền — dấu hiệu nuốt nhiều dòng script)

    Nếu khớp: trả về list các (offset_mới, text_mới, raw_mới, FORMAT_QUOTED_INPLACE)
    — MỖI cặp dấu nháy chứa CJK/Việt trở thành 1 entry riêng, offset được tính
    lại đúng vị trí byte thật trong data gốc, fmt riêng = FORMAT_QUOTED_INPLACE
    để patch_binary() ghi ĐÚNG IN-PLACE, không bao giờ đụng byte nào ngoài
    chính phần text trong dấu nháy.

    Nếu KHÔNG khớp pattern code: trả về None (giữ nguyên xử lý như cũ, fmt = base_fmt).
    """
    _RE_CODE_CALL = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\s*\([^()"]{0,40}["\u201c]')
    _RE_QUOTED = re.compile(r'["\u201c\u300c]([^"\u201d\u300d]{1,300})["\u201d\u300d]')

    looks_like_code = bool(_RE_CODE_CALL.search(text))
    quote_matches = list(_RE_QUOTED.finditer(text))

    if not looks_like_code and len(quote_matches) <= 1:
        return None
    if not quote_matches:
        return None

    new_entries = []
    for m in quote_matches:
        inner = m.group(1).strip()
        if not inner:
            continue
        if not has_target_language(inner):
            continue

        prefix_str = text[:m.start(1)]
        try:
            prefix_bytes_len = len(prefix_str.encode('utf-8'))
        except Exception:
            prefix_bytes_len = len(prefix_str)

        new_offset = offset + prefix_bytes_len
        new_raw = inner.encode('utf-8', errors='replace')
        new_entries.append((new_offset, inner, new_raw, FORMAT_QUOTED_INPLACE))

    return new_entries if new_entries else None


def _post_filter_strings(entries: list, base_fmt: str = FORMAT_UNKNOWN) -> list:
    """
    Lọc thêm sau khi extract toàn bộ từ một file.
    Áp dụng các rule contextual (cần nhìn toàn bộ tập strings):
    - Tách entry "nuốt nguyên dòng code script" (showDlg(1,0,"text")) → chỉ
      giữ phần text trong dấu nháy với fmt riêng = FORMAT_QUOTED_INPLACE,
      KHÔNG bao giờ patch đè lên code xung quanh.
    - Loại bỏ duplicate text (giữ lại offset đầu tiên)
    - Loại bỏ strings trông như resource keys / code tokens
    - Loại bỏ strings trông như số format / template token
    - Kiểm tra thêm tỷ lệ CJK có ý nghĩa

    Trả về list of (offset, text, raw, entry_fmt) — entry_fmt thường == base_fmt,
    trừ các entry đã unwrap thì entry_fmt == FORMAT_QUOTED_INPLACE.
    """
    if not entries:
        return entries

    # ── Bước 0: Unwrap các entry trông như lệnh script bị nuốt nguyên dòng ──
    unwrapped = []
    for offset, text, raw in entries:
        split = _unwrap_script_code_entry(offset, text, raw, base_fmt)
        if split is not None:
            unwrapped.extend(split)
        else:
            unwrapped.append((offset, text, raw, base_fmt))
    entries = unwrapped

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

    for offset, text, raw, entry_fmt in entries:
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
        result.append((offset, t, raw, entry_fmt))

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

        def _should_scan(name: str) -> bool:
            if name.endswith('/'):
                return False
            if name.startswith('META-INF/'):
                return False
            # Scan TẤT CẢ file còn lại, bất kể đuôi mở rộng. Việc loại trừ
            # file binary không chứa text (ảnh/audio/zip/class thật, v.v.)
            # xảy ra ở is_structured_binary() dựa trên MAGIC BYTES nội dung
            # thật, không dựa theo tên file — vì rất nhiều game giả đuôi
            # file (.png, .map, .spr...) để giấu text.
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
                for offset, text, raw, entry_fmt in string_entries:
                    # Lọc strings rác trước khi thêm vào kết quả
                    if not _is_meaningful_string(text):
                        continue
                    key = (name, offset, entry_fmt)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    results.append({
                        'jar_entry':  name,
                        'offset':     offset,
                        'raw':        raw,
                        'fmt':        entry_fmt,   # fmt riêng từng entry — quan trọng cho
                                                     # các entry FORMAT_QUOTED_INPLACE (unwrap
                                                     # từ code script) để patch_binary() không
                                                     # ghi đè length-prefix lên code xung quanh
                        'original':   text,
                        'translated': text,
                        'enabled':    True,
                    })
            except Exception:
                continue
    return results


def patch_jar(jar_path: str, out_path: str, string_list: list, progress_cb=None):
    # Group replacements by (jar_entry, fmt) — QUAN TRỌNG: một file có thể lẫn
    # nhiều fmt khác nhau (ví dụ phần lớn là len2be_utf8, nhưng vài entry bị
    # unwrap từ code script script mang fmt riêng FORMAT_QUOTED_INPLACE).
    # Trước đây code lấy "fmt của item đầu tiên" áp dụng cho TOÀN BỘ entries
    # trong file → nếu file lẫn 2 fmt, các entry fmt khác bị patch SAI cách
    # (ví dụ bị ghi length-prefix đè lên code), nay patch riêng theo từng fmt.
    entry_replacements = {}  # (jar_entry, fmt) → {offset: (new_text, orig_raw, fmt)}
    for item in string_list:
        if not item['enabled']:
            continue
        if item['translated'] == item['original']:
            continue
        ent = item['jar_entry']
        fmt = item['fmt']
        key = (ent, fmt)
        if key not in entry_replacements:
            entry_replacements[key] = {}
        entry_replacements[key][item['offset']] = (
            item['translated'], item['raw'], fmt
        )

    # Map jar_entry → list of fmt cần patch, để biết entry nào cần xử lý
    entries_by_name = {}
    for (ent, fmt) in entry_replacements:
        entries_by_name.setdefault(ent, []).append(fmt)

    with zipfile.ZipFile(jar_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            names = zin.namelist()
            total = len(names)
            for i, name in enumerate(names):
                if progress_cb:
                    progress_cb(i + 1, total, name)
                data = zin.read(name)
                if name in entries_by_name:
                    for fmt in entries_by_name[name]:
                        replacements = entry_replacements[(name, fmt)]
                        try:
                            data = patch_binary(data, fmt, replacements)
                        except Exception as e:
                            print(f"Patch error {name} [{fmt}]: {e}")
                zout.writestr(zipfile.ZipInfo(name), data)


# ─────────────────────────────────────────────
# Translation (Gemini API)
# ─────────────────────────────────────────────

_translate_cache   = {}
_gemini_translator = None

# Tag marker dạng "N@" dùng để gói nhiều trường dữ liệu vào 1 string trong
# nhiều file game (ví dụ "4@mo_ta3@ten_skill"). Phải tách ra trước khi dịch
# để không bị model làm mất cấu trúc.
_RE_TAG_MARKER = re.compile(r'(\d+@)')


class GeminiTranslator:
    """
    Thay thế GoogleTranslator (deep_translator) bằng Gemini API.
    Giữ nguyên interface .translate(text) -> str để không phải sửa
    các hàm translate_batch / translate_single phía dưới.

    Yêu cầu bắt buộc với Gemini:
      - Dịch tiếng Việt KHÔNG DẤU (không dấu thanh, không ký tự có dấu)
      - Ưu tiên dịch ĐÚNG NGHĨA, tự nhiên trước, sau đó mới rút ngắn nếu cần
      - Độ dài kết quả TUYỆT ĐỐI không vượt quá số BYTE UTF-8 của văn bản gốc
        (không phải số ký tự — vì 1 chữ Hán = 3 byte UTF-8, còn 1 chữ Việt
        không dấu = 1 byte ASCII, dùng số ký tự sẽ cắt cụt bản dịch giữa câu)
        → ràng buộc cứng này được code cắt ở tầng hậu xử lý, không bắt
          model phải vừa dịch vừa đếm byte (tránh làm giảm chất lượng dịch).
    """

    SYSTEM_INSTRUCTION = (
        "Ban la chuyen gia dich game tu tieng Trung sang tieng Viet, "
        "chuyen Viet hoa game J2ME/Java. Nhiem vu: dich CHINH XAC, tu nhien, "
        "dung van phong game (vu khi, ky nang, vat pham, hoi thoai, menu...).\n"
        "Quy tac bat buoc:\n"
        "1. Luon viet tieng Viet KHONG DAU: khong dung nguyen am co dau "
        "(a, e, o, u...) va khong dung dau thanh (sac, huyen, hoi, nga, nang).\n"
        "2. Dich ngan gon, sat nghia, khong dien giai thua.\n"
        "3. Chi tra ve DUY NHAT chuoi da dich. Khong giai thich, khong ghi "
        "chu, khong dau ngoac kep, khong xuong dong, khong them tien to."
    )

    def _call_model(self, model: str, user_text: str) -> str:
        """Gọi 1 model cụ thể, trả về text thô (chưa xử lý). Raise nếu lỗi."""
        body = {
            "systemInstruction": {"parts": [{"text": self.SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": user_text}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 512,
                # Tắt/giảm "suy luận ngầm" (thinking) — nếu không, token suy luận
                # ăn hết maxOutputTokens và câu trả lời thật bị cắt cụt giữa câu.
                "thinkingConfig": _thinking_config_for(model),
            },
        }
        resp = requests.post(_gemini_url(model), json=body, timeout=20)

        # ── Bắt lỗi HTTP rõ ràng: in nguyên message lỗi từ Google ──
        if resp.status_code != 200:
            raise RuntimeError(
                f"[{model}] HTTP {resp.status_code}: {resp.text[:400]}"
            )

        data = resp.json()
        candidates = data.get("candidates")
        if not candidates:
            reason = data.get("promptFeedback", {}).get("blockReason", "unknown")
            raise RuntimeError(
                f"[{model}] khong tra ve candidates (blockReason={reason}, "
                f"raw={str(data)[:300]})"
            )

        finish = candidates[0].get("finishReason", "unknown")
        parts = candidates[0].get("content", {}).get("parts")
        if not parts:
            raise RuntimeError(f"[{model}] tra ve rong (finishReason={finish})")

        out = parts[0].get("text", "")
        if not out:
            raise RuntimeError(f"[{model}] chuoi rong sau xu ly (finishReason={finish})")

        # finishReason=MAX_TOKENS nghia la cau tra loi bi cat ngang vi het token
        # (thuong do thinking ngam an het ngan sach) — KHONG nhan ket qua nay,
        # de retry/fallback xu ly thay vi am tham tra ve cau bi cat cut.
        if finish == "MAX_TOKENS":
            raise RuntimeError(f"[{model}] bi cat cut vi het token (finishReason=MAX_TOKENS)")

        return out

    @staticmethod
    def _is_retriable(err_msg: str) -> bool:
        """503 (UNAVAILABLE/quá tải) và 429 (quota/rate limit) là lỗi tạm thời, nên retry/fallback."""
        return ("HTTP 503" in err_msg or "HTTP 429" in err_msg
                or "UNAVAILABLE" in err_msg or "RESOURCE_EXHAUSTED" in err_msg)

    def _translate_plain(self, text: str) -> str:
        """Dịch 1 đoạn text thuần (không chứa tag marker N@) qua Gemini, có retry + fallback model."""
        # QUAN TRỌNG: giới hạn theo SỐ BYTE UTF-8 của văn bản gốc, không phải
        # số ký tự. 1 chữ Hán = 3 byte UTF-8, còn 1 chữ Việt không dấu = 1 byte
        # ASCII, nên ngân sách byte luôn lớn hơn nhiều so với số ký tự Hán.
        # Dùng số ký tự sẽ cắt cụt bản dịch giữa câu (bug đã gặp).
        max_bytes = len(text.encode('utf-8'))
        user_text = (
            f"Do dai van ban goc: {max_bytes} byte UTF-8. Ban dich tieng Viet "
            f"khong dau la ASCII (1 ky tu = 1 byte), nen ban dich co the dai "
            f"toi da {max_bytes} ky tu. Neu dich tu nhien dai hon, hay rut gon "
            f"lai nhung van giu dung y chinh, KHONG cat cut giua cau.\n"
            f"Dich chuoi sau: {text}"
        )

        # Thử model chính trước (chất lượng cao nhất), nếu quá tải/lỗi tạm thời
        # thì retry với backoff, hết lượt thì rớt sang model fallback ổn định hơn.
        plan = [(GEMINI_MODEL_PRIMARY, 2), (GEMINI_MODEL_FALLBACK, 2)]
        last_err = None
        for model, max_attempts in plan:
            for attempt in range(max_attempts):
                try:
                    out = self._call_model(model, user_text)
                    out = out.strip().strip('"').strip("'").splitlines()[0].strip()
                    if not out:
                        raise RuntimeError(f"[{model}] chuoi rong sau xu ly")
                    # An toàn tuyệt đối: cắt cứng theo BYTE, không cắt theo ký tự
                    out_bytes = out.encode('utf-8')
                    if len(out_bytes) > max_bytes:
                        out = out_bytes[:max_bytes].decode('utf-8', errors='ignore')
                    return out
                except Exception as e:
                    last_err = e
                    if self._is_retriable(str(e)) and attempt < max_attempts - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    break  # hết lượt thử model này → chuyển sang model fallback (vòng for ngoài)
        raise last_err

    def translate(self, text: str) -> str:
        """
        Điểm vào chính. Nhiều file game gói nhiều trường dữ liệu vào 1 string
        bằng tag dạng "N@" (ví dụ "4@mo_ta3@ten_skill"). Nếu đưa nguyên cả
        chuỗi cho model, model dễ hiểu sai và LÀM MẤT tag + mất luôn đoạn sau.

        Vì vậy: tách chuỗi theo tag "N@" TRƯỚC khi gửi đi dịch — tag không
        bao giờ được gửi cho model nên không thể bị model làm mất. Mỗi đoạn
        nội dung giữa các tag được dịch riêng, sau đó ghép lại đúng vị trí.
        """
        if _RE_TAG_MARKER.search(text):
            segments = _RE_TAG_MARKER.split(text)
            out_parts = []
            for seg in segments:
                if _RE_TAG_MARKER.fullmatch(seg or ''):
                    out_parts.append(seg)              # giữ nguyên tag, không đưa cho model
                elif seg and has_chinese(seg):
                    out_parts.append(self._translate_plain(seg))
                else:
                    out_parts.append(seg or '')
            return ''.join(out_parts)
        return self._translate_plain(text)


def get_translator():
    global _gemini_translator
    if not TRANSLATOR_OK:
        return None
    if _gemini_translator is None:
        _gemini_translator = GeminiTranslator()
    return _gemini_translator


def translate_batch(items: list, indices: list, accent: bool, progress_cb=None, stop_flag=None):
    """
    Trả về dict {'translated': n, 'failed': n, 'error': str|None} để GUI
    hiển thị rõ kết quả thật, tránh báo 'Dịch xong' trong khi thực tế lỗi.
    """
    tr = get_translator()
    if tr is None:
        return {'translated': 0, 'failed': 0,
                'error': "Khong khoi tao duoc translator (thieu 'pip install requests'?)"}
    total = len(indices)
    translated_count = 0
    failed = 0
    last_error = None
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
            translated_count += 1
        except Exception as e:
            failed += 1
            last_error = str(e)
            print(f"[Gemini] Loi dich '{src_text[:50]}': {e}")

        if progress_cb:
            progress_cb(n + 1, total)
        time.sleep(0.01)

    return {'translated': translated_count, 'failed': failed, 'error': last_error}


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
                print("[Gemini] Khong khoi tao duoc translator (thieu 'pip install requests'?)")
                return src_text
            vi = tr.translate(src_text)
            if vi:
                _translate_cache[src_text] = vi
        if not vi or not vi.strip():
            return src_text
        if not accent and UNIDECODE_OK:
            vi = unidecode(vi)
        return vi
    except Exception as e:
        print(f"[Gemini] Loi dich '{src_text[:50]}': {e}")
        return src_text

class CopyButton(tk.Label):
    def __init__(self, parent, get_text_fn, **kwargs):
        super().__init__(parent, text="⧉", cursor="hand2",
                         font=('Segoe UI', 8), fg='#89b4fa', bg='#1e1e2e',
                         padx=2, pady=0, **kwargs)
        self.get_text_fn = get_text_fn
        self.bind('<Button-1>', self._copy)
        self.bind('<Enter>', lambda e: self.config(fg='#74c7ec'))
        self.bind('<Leave>', lambda e: self.config(fg='#89b4fa'))

    def _copy(self, _=None):
        text = self.get_text_fn()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.config(text='✓', fg='#a6e3a1')
        self.after(800, lambda: self.config(text='⧉', fg='#89b4fa'))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Binary String Translator")
        self.geometry("1200x760")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)

        self.jar_path   = tk.StringVar()
        self.out_path   = tk.StringVar()
        self.accent_var = tk.BooleanVar(value=True)
        self.search_var  = tk.StringVar()
        self.replace_var = tk.StringVar()
        self.fmt_filter  = tk.StringVar(value='All')

        self.all_strings  = []
        self.filtered     = []
        self.current_page = 0
        self._stop_translate = False
        self._fmt_combos  = {}   # iid → (StringVar, Combobox widget)
        self._active_entry = None  # (entry_widget, row_iid) hiện đang edit
        self._search_after_id = None  # debounce id cho realtime search

        self._build_ui()
        # Realtime search: trace search_var
        self.search_var.trace_add('write', self._on_search_changed)

    # ── UI Construction ──

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame',      background='#1e1e2e')
        style.configure('TLabel',      background='#1e1e2e', foreground='#cdd6f4',
                        font=('Segoe UI', 9))
        style.configure('TButton',     background='#313244', foreground='#cdd6f4',
                        font=('Segoe UI', 9), relief='flat', padding=4)
        style.map('TButton',           background=[('active', '#45475a')])
        style.configure('Accent.TButton', background='#89b4fa', foreground='#1e1e2e',
                        font=('Segoe UI', 9, 'bold'))
        style.map('Accent.TButton',    background=[('active', '#74c7ec')])
        style.configure('TEntry',      fieldbackground='#313244', foreground='#cdd6f4',
                        insertcolor='#cdd6f4')
        style.configure('TCheckbutton', background='#1e1e2e', foreground='#cdd6f4')
        style.configure('TProgressbar', troughcolor='#313244', background='#89b4fa')
        style.configure('Treeview',    background='#181825', fieldbackground='#181825',
                        foreground='#cdd6f4', rowheight=22, font=('Segoe UI', 9))
        style.configure('Treeview.Heading', background='#313244', foreground='#89b4fa',
                        font=('Segoe UI', 9, 'bold'))
        style.map('Treeview',          background=[('selected', '#45475a')])

        # ── Row 1: File path ──
        top = ttk.Frame(self, padding=(8, 6))
        top.pack(fill='x')
        ttk.Label(top, text="JAR/ZIP:").pack(side='left')
        ttk.Entry(top, textvariable=self.jar_path, width=52).pack(side='left', padx=4)
        ttk.Button(top, text="Browse…", command=self._browse_jar).pack(side='left')
        ttk.Button(top, text="🔍 Scan", style='Accent.TButton',
                   command=self._start_scan).pack(side='left', padx=8)

        # ── Row 2: Output path ──
        row2 = ttk.Frame(self, padding=(8, 2))
        row2.pack(fill='x')
        ttk.Label(row2, text="Output:").pack(side='left')
        ttk.Entry(row2, textvariable=self.out_path, width=52).pack(side='left', padx=4)
        ttk.Button(row2, text="Browse…", command=self._browse_out).pack(side='left')
        ttk.Button(row2, text="🔧 Patch JAR", style='Accent.TButton',
                   command=self._patch_jar).pack(side='left', padx=16)

        # ── Row 3: Translate controls ──
        ctrl = ttk.Frame(self, padding=(8, 2))
        ctrl.pack(fill='x')
        ttk.Checkbutton(ctrl, text="Có dấu", variable=self.accent_var).pack(side='left')
        ttk.Button(ctrl, text="▶ Dịch tất cả", command=self._translate_all).pack(side='left', padx=6)
        ttk.Button(ctrl, text="▶ Dịch trang này", command=self._translate_page).pack(side='left')
        ttk.Button(ctrl, text="■ Dừng", command=self._stop_translation).pack(side='left', padx=4)
        ttk.Button(ctrl, text="☑ Chọn tất cả", command=self._check_all).pack(side='left', padx=(12, 2))
        ttk.Button(ctrl, text="☐ Bỏ tất cả",  command=self._uncheck_all).pack(side='left', padx=2)

        # ── Row 3b: Format filter ──
        ttk.Label(ctrl, text="  Format:").pack(side='left', padx=(16, 2))
        self.fmt_combo = ttk.Combobox(ctrl, textvariable=self.fmt_filter, width=18,
                                       state='readonly')
        self.fmt_combo['values'] = ['All'] + list(FORMAT_LABELS.values())
        self.fmt_combo.pack(side='left')
        self.fmt_combo.bind('<<ComboboxSelected>>', lambda e: self._apply_filter())

        # ── Row 4: Search & Replace ──
        sr = ttk.Frame(self, padding=(8, 2))
        sr.pack(fill='x')
        ttk.Label(sr, text="Search:").pack(side='left')
        ttk.Entry(sr, textvariable=self.search_var, width=26).pack(side='left', padx=(2, 0))
        CopyButton(sr, lambda: self.search_var.get()).pack(side='left', padx=(1, 6))

        ttk.Label(sr, text="Replace:").pack(side='left')
        ttk.Entry(sr, textvariable=self.replace_var, width=26).pack(side='left', padx=(2, 0))

        paste_btn = tk.Label(sr, text="⬇", cursor="hand2", font=('Segoe UI', 8),
                             fg='#a6e3a1', bg='#1e1e2e', padx=2)
        paste_btn.pack(side='left', padx=(1, 4))
        paste_btn.bind('<Button-1>', self._paste_to_replace)
        paste_btn.bind('<Enter>', lambda e: paste_btn.config(fg='#74c7ec'))
        paste_btn.bind('<Leave>', lambda e: paste_btn.config(fg='#a6e3a1'))

        ttk.Button(sr, text="Replace All", command=self._replace_all).pack(side='left', padx=2)
        ttk.Button(sr, text="Filter",      command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(sr, text="Clear",       command=self._clear_filter).pack(side='left', padx=2)

        # ── Row 5: Status ──
        stat = ttk.Frame(self, padding=(8, 2))
        stat.pack(fill='x')
        self.status_var = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(stat, textvariable=self.status_var).pack(side='left')
        self.progress = ttk.Progressbar(stat, length=280, mode='determinate')
        self.progress.pack(side='left', padx=10)
        self.count_var = tk.StringVar(value="0 strings")
        ttk.Label(stat, textvariable=self.count_var).pack(side='left')

        # ── Treeview ──
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('enabled', 'file', 'fmt', 'offset', 'original', 'cp_orig', 'translated', 'cp_trans', 'tr_btn')
        self.tree = ttk.Treeview(tree_frame, columns=cols, show='headings', selectmode='browse')
        self.tree.heading('enabled',    text='✔')
        self.tree.heading('file',       text='File')
        self.tree.heading('fmt',        text='Format')
        self.tree.heading('offset',     text='Offset')
        self.tree.heading('original',   text='Original (CN/VI)')
        self.tree.heading('cp_orig',    text='')
        self.tree.heading('translated', text='Translated (editable)')
        self.tree.heading('cp_trans',   text='')
        self.tree.heading('tr_btn',     text='▶')

        self.tree.column('enabled',    width=28,  anchor='center', stretch=False)
        self.tree.column('file',       width=140, stretch=False)
        self.tree.column('fmt',        width=130, stretch=False)
        self.tree.column('offset',     width=68,  anchor='e', stretch=False)
        self.tree.column('original',   width=240)
        self.tree.column('cp_orig',    width=22,  anchor='center', stretch=False)
        self.tree.column('translated', width=240)
        self.tree.column('cp_trans',   width=22,  anchor='center', stretch=False)
        self.tree.column('tr_btn',     width=28,  anchor='center', stretch=False)

        vsb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-1>', self._on_click)

        # ── Pager ──
        pager = ttk.Frame(self, padding=(8, 4))
        pager.pack(fill='x')
        ttk.Button(pager, text="◀ Prev", command=self._prev_page).pack(side='left')
        self.page_var = tk.StringVar(value="Page 0 / 0")
        ttk.Label(pager, textvariable=self.page_var).pack(side='left', padx=10)
        ttk.Button(pager, text="Next ▶", command=self._next_page).pack(side='left')

    # ── Clipboard helpers ──

    def _copy_text(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _paste_to_replace(self, _=None):
        try:
            self.replace_var.set(self.clipboard_get())
        except Exception:
            pass

    # ── File dialogs ──

    def _browse_jar(self):
        p = filedialog.askopenfilename(
            filetypes=[("JAR/ZIP files", "*.jar *.zip"), ("All", "*.*")])
        if p:
            self.jar_path.set(p)
            base, ext = os.path.splitext(p)
            self.out_path.set(base + "_vi" + ext)

    def _browse_out(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".jar",
            filetypes=[("JAR/ZIP files", "*.jar *.zip")])
        if p:
            self.out_path.set(p)

    # ── Scan ──

    def _start_scan(self):
        path = self.jar_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Lỗi", "Chọn file JAR/ZIP hợp lệ.")
            return
        self.all_strings = []
        self.filtered = []
        self._clear_tree()
        self.status_var.set("Đang scan...")
        threading.Thread(target=self._scan_thread, args=(path,), daemon=True).start()

    def _scan_thread(self, path):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value']   = i
            self.status_var.set(f"Scan {i}/{total}: {os.path.basename(name)}")

        results = scan_jar(path, progress_cb=cb)
        self.all_strings = results
        self.filtered    = results[:]
        self.current_page = 0

        # Build format stats
        fmt_counts = Counter(item['fmt'] for item in results)
        stats = ' | '.join(f"{FORMAT_LABELS.get(f, f)}: {c}" for f, c in fmt_counts.most_common())

        self.after(0, self._refresh_tree)
        self.after(0, lambda: self.status_var.set(
            f"Scan xong. {len(results)} strings — {stats}"))
        self.after(0, lambda: self.count_var.set(f"{len(results)} strings"))

    # ── Tree rendering ──

    def _refresh_tree(self):
        # Hủy combobox cũ
        for var, combo in self._fmt_combos.values():
            try: combo.destroy()
            except Exception: pass
        self._fmt_combos.clear()

        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        total = len(self.filtered)
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_var.set(f"Page {self.current_page + 1} / {total_pages}")
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, total)
        for i, item in enumerate(self.filtered[start:end]):
            check    = '☑' if item['enabled'] else '☐'
            fname    = os.path.basename(item['jar_entry'])
            fmt_lbl  = FORMAT_KEY_TO_LABEL.get(item['fmt'], FORMAT_LABELS.get(item['fmt'], item['fmt']))
            offset   = f"0x{item['offset']:X}"
            orig     = item['original'][:70]
            trans_v  = item['translated'] or item['original']
            trans    = trans_v[:70]
            tag      = 'translated' if item['translated'] != item['original'] else 'normal'
            iid      = f"row_{start + i}"
            tr_icon  = '↩' if item['translated'] != item['original'] else '▶'
            self.tree.insert('', 'end', iid=iid,
                             values=(check, fname, fmt_lbl, offset, orig, '⧉', trans, '⧉', tr_icon),
                             tags=(tag,))

        self.tree.tag_configure('translated', foreground='#a6e3a1')
        self.tree.tag_configure('normal',     foreground='#cdd6f4')

        # Tạo Combobox overlay trên cột fmt cho từng row
        self.after(10, self._place_fmt_combos)

    def _update_tree_translated(self):
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(self.filtered))
        for i, item in enumerate(self.filtered[start:end]):
            iid = f"row_{start + i}"
            if not self.tree.exists(iid):
                continue
            trans_v  = item['translated'] or item['original']
            trans    = trans_v[:70]
            is_trans = item['translated'] != item['original']
            tag      = 'translated' if is_trans else 'normal'
            self.tree.set(iid, 'translated', trans)
            self.tree.set(iid, 'tr_btn', '↩' if is_trans else '▶')
            self.tree.item(iid, tags=(tag,))

    def _place_fmt_combos(self):
        """Đặt Combobox lên trên cột 'fmt' của từng row hiển thị."""
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(self.filtered))
        for i in range(end - start):
            iid = f"row_{start + i}"
            if not self.tree.exists(iid):
                continue
            if iid in self._fmt_combos:
                continue
            bbox = self.tree.bbox(iid, 'fmt')
            if not bbox:
                continue
            x, y, w, h = bbox
            item = self.filtered[start + i]
            current_lbl = FORMAT_KEY_TO_LABEL.get(
                item['fmt'], FORMAT_LABELS.get(item['fmt'], item['fmt']))
            var = tk.StringVar(value=current_lbl)
            cb = ttk.Combobox(self.tree, textvariable=var,
                              values=FORMAT_DROPDOWN_LABELS,
                              state='readonly', font=('Segoe UI', 8),
                              width=int(w // 7))
            cb.place(x=x, y=y, width=w, height=h)

            def _on_fmt_change(event, _iid=iid, _var=var, _idx=start + i):
                chosen_lbl = _var.get()
                new_fmt    = FORMAT_LABEL_TO_KEY.get(chosen_lbl, self.filtered[_idx]['fmt'])
                item_ref   = self.filtered[_idx]
                item_ref['fmt'] = new_fmt
                # Đồng bộ all_strings
                for s in self.all_strings:
                    if s is item_ref:
                        s['fmt'] = new_fmt
                        break
                # Redecode original text từ raw bytes theo encoding mới
                raw = item_ref.get('raw', b'')
                new_text = _redecode_raw(raw, new_fmt)
                if new_text:
                    item_ref['original']   = new_text
                    item_ref['translated'] = new_text   # reset translated cũng về text mới
                    if self.tree.exists(_iid):
                        self.tree.set(_iid, 'original',   new_text[:70])
                        self.tree.set(_iid, 'translated', new_text[:70])
                        self.tree.set(_iid, 'tr_btn', '▶')
                        self.tree.item(_iid, tags=('normal',))
                    self.status_var.set(
                        f"Re-decode [{new_fmt}]: {new_text[:60]}")
                else:
                    self.status_var.set(
                        f"Không decode được raw bytes với {chosen_lbl}")

            cb.bind('<<ComboboxSelected>>', _on_fmt_change)
            self._fmt_combos[iid] = (var, cb)

    def _clear_tree(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

    # ── Paging ──

    def _prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self._refresh_tree()

    def _next_page(self):
        total_pages = max(1, (len(self.filtered) + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self._refresh_tree()

    # ── Click handlers ──

    def _on_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        col    = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if region != 'cell' or not row_id:
            return
        try:
            idx = int(row_id.replace('row_', ''))
        except ValueError:
            return

        if col == '#1':
            self.filtered[idx]['enabled'] = not self.filtered[idx]['enabled']
            self._refresh_tree()
        elif col == '#6':
            self._copy_text(self.filtered[idx]['original'])
            self.status_var.set(f"Copied: {self.filtered[idx]['original'][:60]}")
        elif col == '#8':
            text = self.filtered[idx]['translated'] or ''
            self._copy_text(text)
            self.status_var.set(f"Copied: {text[:60]}")
        elif col == '#9':
            item = self.filtered[idx]
            if item['translated'] != item['original']:
                # ↩ Rollback về original
                item['translated'] = item['original']
                if self.tree.exists(row_id):
                    self.tree.set(row_id, 'translated', item['original'][:70])
                    self.tree.set(row_id, 'tr_btn', '▶')
                    self.tree.item(row_id, tags=('normal',))
                self.status_var.set(f"Rollback: {item['original'][:60]}")
            else:
                # ▶ Dịch đơn row này
                self._translate_single_row(idx, row_id)

    def _byte_info(self, item: dict, new_text: str) -> str:
        """Trả về chuỗi so sánh byte size: gốc vs bản dịch theo fmt của item."""
        fmt = item.get('fmt', '')
        orig_raw = item.get('raw', b'')
        orig_bytes = len(orig_raw)
        if not new_text:
            return f"Gốc: {orig_bytes}B"
        try:
            new_raw  = _encode_for_format(new_text, fmt)
            new_bytes = len(new_raw)
        except Exception:
            new_bytes = len(new_text.encode('utf-8', errors='replace'))
        diff = new_bytes - orig_bytes
        sign = '+' if diff > 0 else ''
        color = '#f38ba8' if diff > 0 else ('#a6e3a1' if diff < 0 else '#cdd6f4')
        return (f"Gốc: {orig_bytes}B  →  Dịch: {new_bytes}B  [{sign}{diff}B]", color)

    def _on_double_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        col    = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if region != 'cell' or not row_id or col != '#7':
            return
        try:
            idx = int(row_id.replace('row_', ''))
        except ValueError:
            return
        bbox = self.tree.bbox(row_id, col)
        if not bbox:
            return
        x, y, w, h = bbox

        # Hủy entry cũ nếu còn
        if self._active_entry:
            try:
                ae, _ = self._active_entry
                ae.destroy()
            except Exception:
                pass
            self._active_entry = None

        item    = self.filtered[idx]
        current = item['translated'] or ''

        frame = tk.Frame(self.tree, bg='#1e1e2e', bd=0)
        frame.place(x=x, y=y - 22, width=w + 120, height=h + 22)

        # Byte info label phía trên
        byte_result = self._byte_info(item, current)
        info_text, info_color = byte_result if isinstance(byte_result, tuple) else (byte_result, '#cdd6f4')
        byte_lbl = tk.Label(frame, text=info_text, font=('Segoe UI', 7),
                            bg='#1e1e2e', fg=info_color, anchor='w')
        byte_lbl.place(x=0, y=0, width=w + 120, height=20)

        entry = tk.Entry(frame, font=('Segoe UI', 9),
                         bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                         relief='flat', bd=1)
        entry.place(x=0, y=20, width=w, height=h)
        entry.insert(0, current)
        entry.focus_set()
        self._active_entry = (frame, row_id)

        def _update_byte_info(*_):
            result = self._byte_info(item, entry.get())
            txt, col_c = result if isinstance(result, tuple) else (result, '#cdd6f4')
            byte_lbl.config(text=txt, fg=col_c)

        entry.bind('<KeyRelease>', _update_byte_info)

        def save(_=None):
            self.filtered[idx]['translated'] = entry.get()
            frame.destroy()
            self._active_entry = None
            self._update_tree_translated()

        entry.bind('<Return>', save)
        entry.bind('<FocusOut>', lambda e: self.after(100, lambda: save() if self._active_entry else None))
        entry.bind('<Escape>', lambda e: (frame.destroy(), setattr(self, '_active_entry', None)))

    # ── Checkbox helpers ──

    def _check_all(self):
        """Bật checkbox tất cả strings trong filtered (trang hiện tại và toàn bộ filtered)."""
        for item in self.filtered:
            item['enabled'] = True
        self._refresh_tree()
        self.status_var.set(f"Đã chọn tất cả {len(self.filtered)} strings.")

    def _uncheck_all(self):
        """Tắt checkbox tất cả strings trong filtered."""
        for item in self.filtered:
            item['enabled'] = False
        self._refresh_tree()
        self.status_var.set(f"Đã bỏ chọn tất cả {len(self.filtered)} strings.")

    # ── Translation ──

    def _translate_all(self):
        if not self.all_strings:
            messagebox.showinfo("Thông báo", "Chưa scan JAR.")
            return
        self._stop_translate = False
        enabled_indices = [i for i, item in enumerate(self.all_strings) if item.get('enabled', True)]
        if not enabled_indices:
            messagebox.showinfo("Thông báo", "Không có string nào được chọn (checkbox).")
            return
        threading.Thread(target=self._translate_thread,
                         args=(self.all_strings, enabled_indices),
                         daemon=True).start()

    def _translate_page(self):
        if not self.filtered:
            return
        self._stop_translate = False
        start   = self.current_page * PAGE_SIZE
        end     = min(start + PAGE_SIZE, len(self.filtered))
        enabled_indices = [i for i in range(start, end) if self.filtered[i].get('enabled', True)]
        if not enabled_indices:
            messagebox.showinfo("Thông báo", "Không có string nào được chọn (checkbox) trên trang này.")
            return
        threading.Thread(target=self._translate_thread,
                         args=(self.filtered, enabled_indices),
                         daemon=True).start()

    def _stop_translation(self):
        self._stop_translate = True
        self.status_var.set("Đã dừng dịch.")

    def _translate_single_row(self, idx: int, row_id: str):
        """Dịch 1 string, cập nhật cell ngay lập tức không cần refresh toàn bộ."""
        item = self.filtered[idx]
        src  = item['original']
        if not has_chinese(src):
            self.status_var.set(f"Không có tiếng Trung để dịch.")
            return

        self.status_var.set(f"Đang dịch: {src[:50]}…")
        self.tree.set(row_id, 'tr_btn', '⏳')

        def _work():
            accent = self.accent_var.get()
            result = translate_single(src, accent)
            def _done():
                item['translated'] = result
                if self.tree.exists(row_id):
                    self.tree.set(row_id, 'translated', result[:70])
                    self.tree.set(row_id, 'tr_btn', '▶')
                    tag = 'translated' if result != item['original'] else 'normal'
                    self.tree.item(row_id, tags=(tag,))
                if result == src:
                    self.status_var.set("Lỗi dịch — xem console/terminal để biết chi tiết.")
                else:
                    self.status_var.set(f"Dịch xong: {result[:60]}")
            self.after(0, _done)

        threading.Thread(target=_work, daemon=True).start()

    def _safe_refresh(self):
        try:
            self._update_tree_translated()
        except Exception:
            pass

    def _translate_thread(self, items, indices):
        accent = self.accent_var.get()
        total  = len(indices)

        def cb(n, _tot):
            self.progress['maximum'] = total
            self.progress['value']   = n
            self.status_var.set(f"Đang dịch {n}/{total}...")
            if n % 5 == 0:
                self.after(0, self._safe_refresh)

        result = translate_batch(items, indices, accent,
                        progress_cb=cb,
                        stop_flag=lambda: self._stop_translate)
        self.after(0, self._refresh_tree)

        failed = result.get('failed', 0) if result else 0
        if failed:
            err = (result.get('error') or '')[:120]
            msg = f"Dịch xong nhưng có {failed} lỗi — xem console/terminal. Lỗi gần nhất: {err}"
        else:
            msg = f"Dịch xong {total} strings."
        self.after(0, lambda: self.status_var.set(msg))

    # ── Search, Filter, Replace ──

    def _on_search_changed(self, *_):
        """Realtime search: debounce 150ms rồi apply filter."""
        if self._search_after_id is not None:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(150, self._apply_filter)

    def _apply_filter(self):
        q   = self.search_var.get().lower().strip()
        fmt = self.fmt_filter.get()

        def match(item):
            # Format filter
            if fmt != 'All':
                lbl = FORMAT_LABELS.get(item['fmt'], item['fmt'])
                if lbl != fmt:
                    return False
            # Text filter
            if q:
                return q in item['original'].lower() or q in (item['translated'] or '').lower()
            return True

        self.filtered     = [x for x in self.all_strings if match(x)]
        self.current_page = 0
        count = len(self.filtered)
        if q and count == 0:
            self.count_var.set("Không tìm thấy kết quả")
        else:
            self.count_var.set(f"{count} strings")
        self._refresh_tree()

    def _clear_filter(self):
        self.search_var.set('')
        self.fmt_filter.set('All')
        self.filtered     = self.all_strings[:]
        self.current_page = 0
        self.count_var.set(f"{len(self.filtered)} strings")
        self._refresh_tree()

    def _replace_all(self):
        q = self.search_var.get()
        r = self.replace_var.get()
        if not q:
            messagebox.showinfo("Thông báo", "Nhập từ cần tìm.")
            return
        count = sum(1 for item in self.filtered if q in (item['translated'] or ''))
        for item in self.filtered:
            if item['translated'] and q in item['translated']:
                item['translated'] = item['translated'].replace(q, r)
        self._refresh_tree()
        messagebox.showinfo("Replace All", f"Đã replace {count} strings.")

    # ── Patch ──

    def _patch_jar(self):
        src = self.jar_path.get().strip()
        dst = self.out_path.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror("Lỗi", "File JAR nguồn không hợp lệ.")
            return
        if not dst:
            messagebox.showerror("Lỗi", "Chưa chọn file output.")
            return
        changed = sum(1 for x in self.all_strings
                      if x['enabled'] and x['translated'] != x['original'])
        if changed == 0:
            messagebox.showinfo("Thông báo", "Không có string nào thay đổi.")
            return
        if not messagebox.askyesno("Xác nhận", f"Patch {changed} strings → {dst}\n\nTiếp tục?"):
            return
        self.status_var.set("Đang patch...")
        threading.Thread(target=self._patch_thread, args=(src, dst), daemon=True).start()

    def _patch_thread(self, src, dst):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value']   = i
            self.status_var.set(f"Packing {i}/{total}: {os.path.basename(name)}")

        try:
            patch_jar(src, dst, self.all_strings, progress_cb=cb)
            self.after(0, lambda: messagebox.showinfo("Xong", f"Patch thành công!\nOutput: {dst}"))
            self.after(0, lambda: self.status_var.set(f"Patch xong → {dst}"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Lỗi patch", str(e)))
            self.after(0, lambda: self.status_var.set("Lỗi patch."))


# ─────────────────────────────────────────────
if __name__ == '__main__':
    if not TRANSLATOR_OK:
        print("WARNING: pip install requests unidecode")
    app = App()
    app.mainloop()
