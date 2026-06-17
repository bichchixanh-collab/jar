#!/usr/bin/env python3
"""
Binary String Translator - Flask Web App
Stateless architecture: scan → JSON → edit → patch → download
"""

import os, json, uuid, threading, time, base64, tempfile, zipfile
from io import BytesIO
from flask import Flask, request, jsonify, render_template, send_file, abort

# ── Import core engine (strip tkinter imports) ──
import importlib, types, sys

# Stub tkinter trước khi import core
for mod in ['tkinter', 'tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox']:
    sys.modules.setdefault(mod, types.ModuleType(mod))

import core_engine as core  # bin39.py stripped of tkinter đổi tên thành core.py

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

# ── In-memory job store (stateless per-request cho scan nhỏ, job store cho translate) ──
_jobs: dict = {}   # job_id → {'status','progress','total','strings','error'}
_jobs_lock = threading.Lock()

PAGE_SIZE = 30


# ────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────

def _serialise(items: list) -> list:
    """Convert raw bytes → base64 str để JSON-safe."""
    out = []
    for it in items:
        d = dict(it)
        if isinstance(d.get('raw'), (bytes, bytearray)):
            d['raw'] = base64.b64encode(d['raw']).decode()
        out.append(d)
    return out


def _deserialise(items: list) -> list:
    """Convert base64 str → bytes."""
    out = []
    for it in items:
        d = dict(it)
        if isinstance(d.get('raw'), str):
            try:
                d['raw'] = base64.b64decode(d['raw'])
            except Exception:
                d['raw'] = b''
        out.append(d)
    return out


def _fmt_stats(strings: list) -> str:
    from collections import Counter
    counts = Counter(s['fmt'] for s in strings)
    return ' | '.join(
        f"{core.FORMAT_LABELS.get(f, f)}: {c}"
        for f, c in counts.most_common()
    )


# ────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Scan ──

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Upload JAR + scan → trả về JSON strings."""
    if 'jar' not in request.files:
        return jsonify(error='Không có file JAR.'), 400
    f = request.files['jar']
    if not f.filename:
        return jsonify(error='Tên file rỗng.'), 400

    jar_bytes = f.read()
    if not jar_bytes:
        return jsonify(error='File rỗng.'), 400

    # Validate ZIP/JAR
    try:
        with zipfile.ZipFile(BytesIO(jar_bytes)) as _zf:
            pass
    except Exception:
        return jsonify(error='File không phải JAR/ZIP hợp lệ.'), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            'status': 'scanning', 'progress': 0, 'total': 1,
            'strings': [], 'jar_b64': base64.b64encode(jar_bytes).decode(),
            'filename': f.filename, 'error': None,
        }

    def _run():
        try:
            results = []
            def cb(i, total, name):
                with _jobs_lock:
                    job = _jobs.get(job_id)
                    if job:
                        job['progress'] = i
                        job['total']    = total

            # Scan từ bytes (không cần file tạm)
            with zipfile.ZipFile(BytesIO(jar_bytes), 'r') as zf:
                all_entries = zf.namelist()
                _EXT_BLACKLIST = {
                    '.class', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
                    '.mp3', '.ogg', '.wav', '.mid', '.aac', '.jar', '.zip',
                    '.gz', '.bz2', '.mf', '.sf', '.rsa', '.dsa',
                    '.map', '.palet', '.palette', '.pal', '.fnt', '.font',
                    '.tileset', '.tile', '.spr', '.sprite', '.anim',
                    '.idx', '.index', '.lut', '.raw',
                }
                _EXT_ALLOWLIST = {
                    '.bin', '.dat', '.res', '.pak', '.txt', '.ini', '.cfg',
                    '.xse', '.xs', '.scr', '.tbl', '.db', '.msg', '.arc',
                    '.xml', '.json', '.csv', '.lang', '.lng', '.str', '.string',
                    '.prop', '.properties', '.conf', '.config',
                }

                def _should_scan(name):
                    if name.endswith('/') or name.startswith('META-INF/'):
                        return False
                    ext = os.path.splitext(name)[1].lower()
                    if ext in _EXT_BLACKLIST:
                        return False
                    if not ext or ext in _EXT_ALLOWLIST:
                        return True
                    return True

                entries = [n for n in all_entries if _should_scan(n)]
                total = len(entries)
                seen_keys = set()

                for i, name in enumerate(entries):
                    with _jobs_lock:
                        job = _jobs.get(job_id)
                        if job:
                            job['progress'] = i + 1
                            job['total']    = total
                    try:
                        data = zf.read(name)
                        basename = os.path.basename(name)
                        if not core.is_structured_binary(data, basename):
                            continue
                        fmt, string_entries = core.extract_strings_from_binary(data, basename)
                        if not string_entries:
                            continue
                        for offset, text, raw in string_entries:
                            if not core._is_meaningful_string(text):
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

            with _jobs_lock:
                job = _jobs.get(job_id)
                if job:
                    job['strings'] = _serialise(results)
                    job['status']  = 'done'
        except Exception as e:
            with _jobs_lock:
                job = _jobs.get(job_id)
                if job:
                    job['status'] = 'error'
                    job['error']  = str(e)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify(job_id=job_id)


@app.route('/api/scan/status/<job_id>')
def api_scan_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify(error='Job không tồn tại.'), 404
    resp = {
        'status':   job['status'],
        'progress': job['progress'],
        'total':    job['total'],
        'error':    job.get('error'),
    }
    if job['status'] == 'done':
        strings = job['strings']
        resp['count']    = len(strings)
        resp['fmt_stats'] = _fmt_stats(_deserialise(strings))
        resp['strings']  = strings   # full list
        resp['filename'] = job.get('filename', '')
        resp['jar_b64']  = job.get('jar_b64', '')  # trả về JAR để patch sau
    return jsonify(resp)


# ── Translate ──

@app.route('/api/translate', methods=['POST'])
def api_translate():
    """Dịch batch strings, trả về list translated."""
    body = request.get_json(silent=True) or {}
    strings  = _deserialise(body.get('strings', []))
    indices  = body.get('indices', list(range(len(strings))))
    accent   = body.get('accent', True)

    if not strings:
        return jsonify(error='Không có strings.'), 400

    results = []
    tr = core.get_translator()
    if tr is None:
        return jsonify(error='deep-translator chưa cài. pip install deep-translator'), 500

    for idx in indices:
        if idx < 0 or idx >= len(strings):
            continue
        item = strings[idx]
        src = item['original']
        if core.has_chinese(src):
            try:
                if src in core._translate_cache:
                    vi = core._translate_cache[src]
                else:
                    vi = tr.translate(src)
                    if vi:
                        core._translate_cache[src] = vi
                if vi and vi.strip():
                    if not accent:
                        try:
                            from unidecode import unidecode
                            vi = unidecode(vi)
                        except ImportError:
                            pass
                    item['translated'] = vi
            except Exception:
                pass
        results.append({'idx': idx, 'translated': item['translated']})
        time.sleep(0.01)

    return jsonify(results=results)


# ── Patch ──

@app.route('/api/patch', methods=['POST'])
def api_patch():
    """Nhận JAR (base64) + strings → trả về patched JAR download."""
    body = request.get_json(silent=True) or {}
    jar_b64  = body.get('jar_b64', '')
    strings  = _deserialise(body.get('strings', []))
    filename = body.get('filename', 'output.jar')

    if not jar_b64:
        return jsonify(error='Thiếu jar_b64.'), 400
    if not strings:
        return jsonify(error='Thiếu strings.'), 400

    try:
        jar_bytes = base64.b64decode(jar_b64)
    except Exception:
        return jsonify(error='jar_b64 không hợp lệ.'), 400

    # Đổi tên output
    base, ext = os.path.splitext(filename)
    out_name  = base + '_vi' + (ext or '.jar')

    try:
        # Gom replacements theo jar_entry
        entry_repl = {}
        for item in strings:
            if not item.get('enabled', True):
                continue
            if item['translated'] == item['original']:
                continue
            ent = item['jar_entry']
            if ent not in entry_repl:
                entry_repl[ent] = {}
            entry_repl[ent][item['offset']] = (
                item['translated'], item['raw'], item['fmt']
            )

        if not entry_repl:
            return jsonify(error='Không có string nào thay đổi.'), 400

        out_buf = BytesIO()
        with zipfile.ZipFile(BytesIO(jar_bytes), 'r') as zin:
            with zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED) as zout:
                for name in zin.namelist():
                    data = zin.read(name)
                    if name in entry_repl:
                        first = next(iter(entry_repl[name].values()))
                        fmt = first[2]
                        try:
                            data = core.patch_binary(data, fmt, entry_repl[name])
                        except Exception as e:
                            print(f'Patch error {name}: {e}')
                    zout.writestr(zipfile.ZipInfo(name), data)

        out_buf.seek(0)
        return send_file(
            out_buf,
            mimetype='application/java-archive',
            as_attachment=True,
            download_name=out_name,
        )
    except Exception as e:
        return jsonify(error=f'Lỗi patch: {e}'), 500


# ── Format change / re-decode ──

@app.route('/api/redecode', methods=['POST'])
def api_redecode():
    """Re-decode raw bytes với format mới."""
    body    = request.get_json(silent=True) or {}
    raw_b64 = body.get('raw', '')
    new_fmt = body.get('fmt', '')
    if not raw_b64 or not new_fmt:
        return jsonify(error='Thiếu raw hoặc fmt.'), 400
    try:
        raw  = base64.b64decode(raw_b64)
        text = core._redecode_raw(raw, new_fmt)
        if text is None:
            return jsonify(error='Không decode được.'), 400
        return jsonify(text=text)
    except Exception as e:
        return jsonify(error=str(e)), 500


# ── Cleanup old jobs (> 30 phút) ──

def _cleanup_loop():
    while True:
        time.sleep(300)
        cutoff = time.time() - 1800
        with _jobs_lock:
            old = [k for k, v in _jobs.items()
                   if v.get('_ts', time.time()) < cutoff]
            for k in old:
                del _jobs[k]

threading.Thread(target=_cleanup_loop, daemon=True).start()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
