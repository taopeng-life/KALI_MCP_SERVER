#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_server.py — 单一 Web 入口（JSON-RPC 2.0）+ 通用“声明式”命令构建引擎（从 config.json 加载）

Endpoints:
- POST /        : JSON-RPC 2.0
    * initialize
    * tools/list
    * tools/call                 （同步；arguments.async=true 或 progress="poll" → 异步）
    * tools/spawn                （总是异步，立即返回 job_id）
    * jobs/poll                  （长轮询增量日志）
    * jobs/cancel
- GET  /jobs/{job_id}/sse        : 实时日志（Server-Sent Events）
- GET  /capabilities_ext         : 能力自描述（含二进制可用性/版本、默认值、build 摘要）
- GET  /health                   : 探活（免鉴权）
- GET  /                         : 简要说明

特点：
- 不再有 Python per-tool builder。所有工具的 bin/入参/默认值/命令拼装，全部在 config.json 中声明。
- 通用构建引擎支持：字符串插值（含过滤器）、条件 when、switch、多层嵌套。
- 统一超时策略：ignore_timeout + default_timeout + hard_timeout_cap_sec。
- 结构化 JSON 日志（req_id/job_id）。
- 支持并发闸门、SSE、长轮询。
"""

import asyncio
import contextvars
import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import FastAPI, Body, APIRouter, Response, Request, Path
from fastapi.responses import JSONResponse, StreamingResponse

# ================== 日志 ==================
logger = logging.getLogger("mcp")
if not logger.handlers:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(message)s")  # 输出 JSON 行

REQ_ID: contextvars.ContextVar[str] = contextvars.ContextVar("req_id", default="-")
JOB_ID: contextvars.ContextVar[str] = contextvars.ContextVar("job_id", default="-")

def logj(level: int, event: str, **fields):
    base = {"ts": round(time.time(), 3), "event": event,
            "req_id": REQ_ID.get("-"), "job_id": JOB_ID.get("-")}
    base.update(fields)
    try:
        logger.log(level, json.dumps(base, ensure_ascii=False))
    except Exception:
        logger.log(level, f"[logj-fallback] {event} {fields}")

# ================== 配置加载 ==================
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config.json")

def _load_config(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

CONFIG: Dict[str, Any] = _load_config(CONFIG_PATH)

def cfg(path: str, default=None):
    cur = CONFIG
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur

# ================== 全局参数（配置优先，其次 env） ==================
API_KEY = os.environ.get("API_KEY")  # 鉴权 header：x-api-key
SLOW_THRESHOLD_SEC = float(os.environ.get("SLOW_THRESHOLD_SEC", "3.0"))

DEFAULT_TIMEOUT = int(cfg("server.default_timeout", os.environ.get("DEFAULT_TIMEOUT", "0")))
IGNORE_TIMEOUT  = bool(cfg("server.ignore_timeout", str(os.environ.get("IGNORE_TIMEOUT", "0")).lower() in ("1","true","yes")))
HARD_TIMEOUT_CAP = int(cfg("server.hard_timeout_cap_sec", os.environ.get("HARD_TIMEOUT_CAP_SEC", "0")) or 0)

JOB_MAX_LINES = int(cfg("server.job_max_lines", os.environ.get("JOB_MAX_LINES", "5000")))
JOB_MAX_BYTES = int(cfg("server.job_max_bytes", os.environ.get("JOB_MAX_BYTES", "0")) or 0)
MAX_CONCUR = int(cfg("server.max_concurrent_jobs", os.environ.get("MAX_CONCURRENT_JOBS", "0")) or 0)

# ================== FastAPI ==================
app = FastAPI(title="MCP (config-driven tools)", version="5.0.0")
router = APIRouter()

# 鉴权中间件：/ 与 /health 放行
@app.middleware("http")
async def _auth_mw(request: Request, call_next):
    if API_KEY:
        p = request.url.path
        if p not in ("/", "/health"):
            if request.headers.get("x-api-key") != API_KEY:
                return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)

# ================== 公共工具函数 ==================
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
def _strip_ansi(b: bytes) -> str:
    return ANSI_ESCAPE_RE.sub("", b.decode("utf-8", errors="replace"))

async def which(bin_name: str) -> bool:
    p = await asyncio.create_subprocess_exec(
        "which", bin_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, _ = await p.communicate()
    return p.returncode == 0 and out.decode().strip() != ""

async def _bin_version(bin_name: str) -> Optional[str]:
    for args in (["--version"], ["-version"], ["version"]):
        try:
            p = await asyncio.create_subprocess_exec(
                bin_name, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out, err = await asyncio.wait_for(p.communicate(), timeout=3)
            text = (out or err).decode("utf-8", errors="replace").splitlines()
            if text:
                return text[0].strip()
        except Exception:
            continue
    return None

# ================== 端口别名解析 & scale 归一 ==================
def _resolve_ports(value: str) -> str:
    profiles = cfg("assets.port_profiles", {}) or {}
    if isinstance(value, str) and value in profiles:
        return profiles[value]
    return value

def _norm_scale(v: Any) -> str:
    s = str(v or "auto").lower().strip()
    if s not in {"auto", "fast", "deep"}:
        s = "auto"
    return "fast" if s == "auto" else s

# ================== 并发闸门 ==================
JOB_SEM = asyncio.Semaphore(MAX_CONCUR) if MAX_CONCUR > 0 else None

# ================== 统一执行（含超时策略、字节裁剪、结构化日志） ==================
async def run_cmd(cmd: List[str], timeout: Optional[int], stdin_data: Optional[str] = None) -> Dict[str, Any]:
    # 统一 timeout：忽略客户端或应用硬上限
    to = 0 if IGNORE_TIMEOUT else int(timeout or 0)
    if HARD_TIMEOUT_CAP and (to <= 0 or to > HARD_TIMEOUT_CAP):
        to = HARD_TIMEOUT_CAP

    env = {**os.environ, "TERM":"dumb","NO_COLOR":"1","CLICOLOR":"0","PYTHONIOENCODING":"utf-8"}

    t0 = time.time()
    logj(logging.INFO, "proc_start", cmd=" ".join(cmd), timeout=to)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    try:
        if stdin_data and proc.stdin:
            proc.stdin.write(stdin_data.encode("utf-8"))
            try:    await proc.stdin.drain()
            except: pass
            try:    proc.stdin.close()
            except: pass

        async def _communicate():
            return await proc.communicate()

        if to > 0:
            stdout_b, stderr_b = await asyncio.wait_for(_communicate(), timeout=to)
        else:
            stdout_b, stderr_b = await _communicate()

        if JOB_MAX_BYTES and (len(stdout_b) + len(stderr_b)) > JOB_MAX_BYTES:
            keep = max(1024, JOB_MAX_BYTES // 2)
            stdout_b = stdout_b[-keep:]
            stderr_b = stderr_b[-keep:]

        rc = proc.returncode
        elapsed = round(time.time() - t0, 3)
        lvl = logging.WARNING if (elapsed >= SLOW_THRESHOLD_SEC or rc != 0) else logging.INFO
        logj(lvl, "proc_done", rc=rc, elapsed=elapsed, out=len(stdout_b), err=len(stderr_b))

        return {
            "cmd": " ".join(cmd),
            "stdout": _strip_ansi(stdout_b),
            "stderr": _strip_ansi(stderr_b),
            "return_code": rc,
            "success": rc == 0,
            "elapsed_sec": elapsed,
        }

    except asyncio.TimeoutError:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
        elapsed = round(time.time() - t0, 3)
        logj(logging.WARNING, "proc_killed", reason="timeout", elapsed=elapsed, cap=to)
        return {
            "cmd": " ".join(cmd), "stdout": "", "stderr": f"超时（{to}s）",
            "return_code": -1, "success": False, "timed_out": True, "elapsed_sec": elapsed,
        }
    except Exception as e:
        elapsed = round(time.time() - t0, 3)
        logj(logging.ERROR, "proc_exception", err=str(e), elapsed=elapsed)
        return {
            "cmd": " ".join(cmd), "stdout": "", "stderr": f"执行错误: {e}",
            "return_code": -1, "success": False, "elapsed_sec": elapsed,
        }

# ================== 声明式命令构建引擎 ==================
"""
配置说明（每个 tool）：
{
  "bin": "nmap",
  "desc": "端口/服务探测（nmap）",
  "enabled": true,
  "params": { "host":{"type":"str","required":true}, "ports":{"type":"str","default":"top-1000"}, ... },
  "defaults": { ... },                # 可选；会覆盖 params 里的 default
  "build": [                           # 构建规则（数组，顺序输出 token；支持嵌套）
    "nmap", "-Pn", "-n",
    {"when": {"eq": ["scale","fast"]}, "emit": ["-T4","-sS"], "else": ["-T4","-sS","-sV","-sC"]},
    {"switch": "ports", "cases": [
      {"startswith": "top-", "emit": ["--top-ports", "${ports|after:top-}"]},
      {"in": ["-","full","all","p-"], "emit": ["-p-"]},
      {"else": ["-p","${ports|resolve_ports}"]}
    ]},
    {"when": {"is_true":"udp"}, "emit": ["-sU"]},
    {"when": {"nonempty":"scripts"}, "emit": ["--script","${scripts}"]},
    "${host}"
  ]
}

- 字符串 token：支持 ${param} 插值，带过滤器：|lower |upper |resolve_ports |after:prefix
- 对象 token：
  * {"when": <cond>, "emit": [..], "else": [..]}    cond 见下
  * {"switch": "param", "cases": [ {"equals": "x", "emit":[..]}, {"startswith":"top-", "emit":[..]}, {"in":["a","b"], "emit":[..]}, {"else":[..]} ]}
  * 也可直接写 {"emit":[..]}（总是展开）
- 条件 cond：
  {"is_true":"p"} / {"is_false":"p"} / {"nonempty":"p"} / {"empty":"p"}
  {"eq":["p",val]} / {"ne":["p",val]} / {"gt":["p",n]} / {"lt":["p",n]}
  {"in":["p",[v1,v2,...]]} / {"startswith":["p","top-"]}
  {"and":[cond1,cond2,...]} / {"or":[cond1,cond2,...]} / {"not":cond}
"""
def _get_param(params: Dict[str, Any], key: str) -> Any:
    return params.get(key)

def _eval_cond(cond: Any, params: Dict[str, Any]) -> bool:
    if not cond:
        return True
    if isinstance(cond, dict):
        if "is_true" in cond:  return bool(_get_param(params, cond["is_true"]))
        if "is_false" in cond: return not bool(_get_param(params, cond["is_false"]))
        if "nonempty" in cond:
            v = _get_param(params, cond["nonempty"]); return (v is not None and str(v) != "")
        if "empty" in cond:
            v = _get_param(params, cond["empty"]); return (v is None or str(v) == "")
        if "eq" in cond:
            p, val = cond["eq"]; return _get_param(params, p) == val
        if "ne" in cond:
            p, val = cond["ne"]; return _get_param(params, p) != val
        if "gt" in cond:
            p, n = cond["gt"]; 
            try: return float(_get_param(params, p)) > float(n)
            except: return False
        if "lt" in cond:
            p, n = cond["lt"]; 
            try: return float(_get_param(params, p)) < float(n)
            except: return False
        if "in" in cond:
            p, arr = cond["in"]; return _get_param(params, p) in arr
        if "startswith" in cond:
            p, pref = cond["startswith"]; 
            v = str(_get_param(params, p) or ""); return v.startswith(pref)
        if "and" in cond:
            return all(_eval_cond(c, params) for c in cond["and"])
        if "or" in cond:
            return any(_eval_cond(c, params) for c in cond["or"])
        if "not" in cond:
            return not _eval_cond(cond["not"], params)
    # 非法 cond → 视为 False
    return False

def _apply_filter(val: str, filt: str) -> str:
    if ":" in filt:
        name, arg = filt.split(":", 1)
    else:
        name, arg = filt, ""
    name = name.strip()
    if name == "lower": return val.lower()
    if name == "upper": return val.upper()
    if name == "resolve_ports": return _resolve_ports(val)
    if name == "after": 
        return val[len(arg):] if val.startswith(arg) else val
    return val

_VAR_RE = re.compile(r"\$\{([A-Za-z0-9_]+)(\|[A-Za-z0-9_:|-]+)*\}")

def _interpolate(token: str, params: Dict[str, Any]) -> str:
    def _repl(m):
        key = m.group(1)
        filters = m.group(2) or ""
        val = "" if _get_param(params, key) is None else str(_get_param(params, key))
        if filters:
            for f in filters.strip("|").split("|"):
                val = _apply_filter(val, f)
        return val
    return _VAR_RE.sub(_repl, token)

def _flatten_tokens(spec: Any, params: Dict[str, Any], acc: List[str]):
    # spec: str | list | dict
    if spec is None:
        return
    if isinstance(spec, str):
        acc.append(_interpolate(spec, params))
        return
    if isinstance(spec, list):
        for it in spec:
            _flatten_tokens(it, params, acc)
        return
    if isinstance(spec, dict):
        if "emit" in spec and "when" not in spec and "switch" not in spec:
            _flatten_tokens(spec["emit"], params, acc)
            return
        if "when" in spec:
            if _eval_cond(spec["when"], params):
                _flatten_tokens(spec.get("emit"), params, acc)
            else:
                _flatten_tokens(spec.get("else"), params, acc)
            return
        if "switch" in spec:
            p = spec["switch"]
            val = _get_param(params, p)
            matched = False
            for case in spec.get("cases", []):
                if "equals" in case and val == case["equals"]:
                    _flatten_tokens(case.get("emit"), params, acc); matched = True; break
                if "startswith" in case and str(val or "").startswith(case["startswith"]):
                    _flatten_tokens(case.get("emit"), params, acc); matched = True; break
                if "in" in case and val in case["in"]:
                    _flatten_tokens(case.get("emit"), params, acc); matched = True; break
                if "when" in case and _eval_cond(case["when"], params):
                    _flatten_tokens(case.get("emit"), params, acc); matched = True; break
            if not matched:
                for case in spec.get("cases", []):
                    if "else" in case:
                        _flatten_tokens(case.get("else"), params, acc); break
            return
    # 其他类型忽略

def build_command_from_config(tool: Dict[str, Any], params: Dict[str, Any]) -> List[str]:
    bin_name = tool.get("bin")
    build = tool.get("build", [])
    tokens: List[str] = []
    if not isinstance(build, list):
        raise ValueError("tool.build must be a list")
    # 允许 build 里不写 bin，则我们自动把 bin 放到最前
    tokens.append(str(bin_name))
    _flatten_tokens(build, params, tokens)
    # 过滤空 token
    return [t for t in tokens if str(t).strip() != ""]

# ================== Tools Registry（从配置加载） ==================
"""
CONFIG["tools"] 结构：
{
  "httpx": {
    "enabled": true,
    "bin": "httpx",
    "desc": "Web 存活与指纹（ProjectDiscovery）",
    "params": {
      "url": {"type":"str","required":true},
      "title":{"type":"bool","default":true},
      "tech_detect":{"type":"bool","default":true},
      "follow_redirects":{"type":"bool","default":true},
      "scale":{"type":"str","default":"auto","enum":["auto","fast","deep"]},
      "timeout":{"type":"int","default":0}
    },
    "defaults": { "scale": "fast", "timeout": 0 },   # 可选
    "build": [ "httpx", "-status-code", {"when":{"is_true":"title"}, "emit":["-title"]}, ... , "-u", "${url}" ]
  },
  ...
}
"""

TOOLS: Dict[str, Dict[str, Any]] = cfg("tools", {}) or {}

def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool): return v
    s = str(v).strip().lower()
    return s in ("1","true","yes","on")

def _coerce_int(v: Any) -> int:
    try: return int(v)
    except: return 0

def _merge_args_with_defaults(tool: Dict[str, Any], arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    params_spec: Dict[str, Any] = tool.get("params", {}) or {}
    defaults_cfg: Dict[str, Any] = tool.get("defaults", {}) or {}
    merged: Dict[str, Any] = {}

    # 规范 & 默认
    for key, spec in params_spec.items():
        typ = str(spec.get("type","str")).lower()
        required = bool(spec.get("required", False))
        enum = spec.get("enum")
        default_val = defaults_cfg.get(key, spec.get("default"))

        if key in arguments:
            val = arguments[key]
        else:
            val = default_val

        # 基本类型转换
        if typ in ("int","integer"):
            val = _coerce_int(val)
        elif typ in ("bool","boolean"):
            val = _coerce_bool(val)
        else:
            if val is None: val = ""

        # enum 校验
        if enum and val not in enum:
            return {}, f"Invalid value for {key}, expected {enum}"

        if required and (val is None or (typ=="str" and str(val)=="")):
            return {}, f"Missing required param: {key}"

        merged[key] = val

    # 允许额外字段透传（但不参与校验）
    for k, v in arguments.items():
        if k not in merged:
            merged[k] = v

    # scale 归一（如存在）
    if "scale" in merged:
        merged["scale"] = _norm_scale(merged["scale"])

    # 兼容：若配置里定义了 ports，用户传入的字符串别名可在 build 阶段用 filter 解析
    return merged, None

def _params_to_jsonschema(params_spec: Dict[str, Any]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    req: List[str] = []
    for k, spec in params_spec.items():
        t = str(spec.get("type","str")).lower()
        js = "string" if t=="str" else ("integer" if t in ("int","integer") else ("boolean" if t in ("bool","boolean") else "string"))
        p: Dict[str, Any] = {"type": js}
        if "default" in spec and spec["default"] is not None: p["default"] = spec["default"]
        if "enum" in spec and spec["enum"]: p["enum"] = spec["enum"]
        props[k] = p
        if spec.get("required"): req.append(k)
    return {"$schema":"http://json-schema.org/draft-07/schema#",
            "type":"object","additionalProperties":False,"properties":props,"required":req}

def _tools_list_payload() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for name, tool in TOOLS.items():
        if tool.get("enabled", True):
            out.append({
                "name": name,
                "description": tool.get("desc",""),
                "inputSchema": _params_to_jsonschema(tool.get("params", {}))
            })
    return out

# ================== Job Registry（spawn + poll + SSE） ==================
@dataclass
class Job:
    id: str
    name: str
    cmd: List[str]
    start_ts: float = field(default_factory=time.time)
    done: bool = False
    rc: Optional[int] = None
    buffer: List[str] = field(default_factory=list)
    cursor0: int = 0
    proc: Optional[asyncio.subprocess.Process] = None
    event: asyncio.Event = field(default_factory=asyncio.Event)
    stdin_data: Optional[str] = None
    last_touch: float = field(default_factory=time.time)

JOBS: Dict[str, Job] = {}
JOBS_LOCK = asyncio.Lock()

async def _append_line(job: Job, line: bytes, tag: str):
    txt = _strip_ansi(line).rstrip("\r\n")
    if tag:
        txt = f"[{tag}] {txt}"
    job.buffer.append(txt)
    if len(job.buffer) > JOB_MAX_LINES:
        drop = len(job.buffer) - JOB_MAX_LINES
        del job.buffer[:drop]
        job.cursor0 += drop
    job.event.set()
    job.last_touch = time.time()

async def _drain_stream(stream: asyncio.StreamReader, job: Job, tag: str):
    while True:
        chunk = await stream.readline()
        if not chunk:
            break
        await _append_line(job, chunk, tag)

async def _spawn_job(cmd: List[str], stdin_data: Optional[str], name: str) -> Job:
    if JOB_SEM:
        await JOB_SEM.acquire()

    job = Job(id=str(uuid.uuid4()), name=name, cmd=cmd, stdin_data=stdin_data)
    JOB_ID.set(job.id)
    logj(logging.INFO, "job_started", tool=name, cmd=" ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "TERM":"dumb","NO_COLOR":"1","CLICOLOR":"0","PYTHONIOENCODING":"utf-8"},
    )
    job.proc = proc

    async def _writer():
        if stdin_data and proc.stdin:
            proc.stdin.write(stdin_data.encode("utf-8"))
            try:    await proc.stdin.drain()
            except: pass
            try:    proc.stdin.close()
            except: pass

    async def _runner():
        try:
            await asyncio.gather(
                _writer(),
                _drain_stream(proc.stdout, job, "stdout") if proc.stdout else asyncio.sleep(0),
                _drain_stream(proc.stderr, job, "stderr") if proc.stderr else asyncio.sleep(0),
            )
            rc = await proc.wait()
            job.rc = rc
            job.done = True
            job.event.set()
            job.last_touch = time.time()
            logj(logging.INFO, "job_finished", tool=name, rc=rc, elapsed=round(time.time()-job.start_ts,3))
        finally:
            if JOB_SEM:
                JOB_SEM.release()

    asyncio.create_task(_runner())
    async with JOBS_LOCK:
        JOBS[job.id] = job
    return job

async def _gc_jobs():
    now = time.time()
    stale: List[str] = []
    ttl = int(cfg("server.job_ttl_sec", os.environ.get("JOB_TTL_SEC", "3600")))
    async with JOBS_LOCK:
        for jid, j in JOBS.items():
            if j.done and (now - j.last_touch) > ttl:
                stale.append(jid)
        for jid in stale:
            del JOBS[jid]
    if stale:
        logj(logging.INFO, "job_gc", removed=len(stale))

# ================== 核心：工具调用（构建引擎） ==================
def _redact_args(args: Dict[str, Any]) -> Dict[str, Any]:
    mask = {"api_key","api-token","api_token","token","password","pass","secret"}
    return {k: ("***" if isinstance(k,str) and k.lower() in mask else v) for k,v in (args or {}).items()}

async def call_local_tool(name: str, arguments: Dict[str, Any], stdin: Optional[str]):
    tool = TOOLS.get(name)
    if not tool:
        return None, {"code": -32601, "message": f"Unknown tool: {name}"}
    if not tool.get("enabled", True):
        return None, {"code": -32601, "message": f"Tool disabled: {name}"}

    # 参数合并/校验/归一
    p, err = _merge_args_with_defaults(tool, arguments or {})
    if err:
        return None, {"code": -32602, "message": err}

    # 文件存在性（wordlist 等）
    if "wordlist" in p and p["wordlist"]:
        try:
            if not os.path.exists(str(p["wordlist"])):  # type: ignore
                return None, {"code": -32602, "message": f"Wordlist not found: {p['wordlist']}"}
        except Exception:
            pass

    # 构建命令（纯 config）
    try:
        cmd = build_command_from_config(tool, p)
        if not isinstance(cmd, list) or not cmd:
            return None, {"code": -32603, "message": "Command build failed"}
    except Exception as e:
        return None, {"code": -32602, "message": f"Command build exception: {e}"}

    # 可执行文件存在性
    bin_name = tool.get("bin")
    if shutil.which(bin_name) is None:
        return None, {"code": -32603, "message": f"Binary not found in PATH: {bin_name}"}

    # 异步 or 同步
    async_mode = bool(arguments.get("async")) or (arguments.get("progress") == "poll")
    if async_mode:
        job = await _spawn_job(cmd, stdin, name)
        await _gc_jobs()
        return {"name": name, "output": {"async": True, "job_id": job.id, "cmd": " ".join(cmd)}}, None

    timeout = 0 if IGNORE_TIMEOUT else p.get("timeout", DEFAULT_TIMEOUT)
    logj(logging.INFO, "tool_exec", name=name, timeout=timeout, args=_redact_args(p))
    out = await run_cmd(cmd, timeout=timeout, stdin_data=stdin)
    await _gc_jobs()
    return {"name": name, "output": out}, None

# ================== MCP：JSON-RPC ==================
def rpc_result(result: Any, _id: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": _id, "result": result}

def rpc_error(code: int, message: str, _id: Any = None, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None: err["data"] = data
    return {"jsonrpc": "2.0", "id": _id, "error": err}

async def mcp_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": "2024-11-05",
        "serverInfo": {"name": "MCP-Proxy-Config", "version": "5.0.0"},
        "capabilities": {"tools": {"list": True, "call": True}},
    }

async def mcp_tools_list(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"tools": _tools_list_payload()}

async def mcp_tools_call(params: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(params, dict): raise ValueError("params must be object")
    name = params.get("name")
    if not isinstance(name, str) or name not in TOOLS:
        raise ValueError("Invalid or missing 'name'")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict): raise ValueError("'arguments' must be object")
    stdin = params.get("stdin")
    if stdin is not None and not isinstance(stdin, str): raise ValueError("'stdin' must be string")

    ok, err = await call_local_tool(name, arguments, stdin)
    if err:
        msg = f"[{name}] error: {err.get('message')}"
        if "data" in err:
            try: msg += "\n" + json.dumps(err["data"], ensure_ascii=False, indent=2)
            except Exception: msg += f"\n{err['data']}"
        return {"content": [{"type":"text","text": msg}], "isError": True}

    out = ok.get("output", {})
    if isinstance(out, dict) and ("stdout" in out or "stderr" in out):
        cmd = out.get("cmd"); stdout = out.get("stdout","")
        text = (f"$ {cmd}\n" if cmd else "") + stdout
        return {"content":[{"type":"text","text":text}], "isError": not out.get("success", True)}
    return {"content":[{"type":"text","text": json.dumps(out, ensure_ascii=False, indent=2)}], "isError": False}

METHODS = {"initialize": mcp_initialize, "tools/list": mcp_tools_list, "tools/call": mcp_tools_call}

async def handle_rpc_payload(payload: Union[Dict[str, Any], List[Any]]) -> Optional[Union[Dict[str, Any], List[Any]]]:
    async def _handle(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(obj, dict): return rpc_error(-32600, "Invalid Request", None)
        jsonrpc = obj.get("jsonrpc"); _id = obj.get("id", None); method = obj.get("method"); params = obj.get("params", {})
        if jsonrpc != "2.0" or not isinstance(method, str): return rpc_error(-32600, "Invalid Request", _id)
        if "id" not in obj:  # notification
            h = METHODS.get(method); 
            try:
                if h: await h(params if isinstance(params, dict) else {})
            except Exception: pass
            return None
        func = METHODS.get(method)
        if func is None: return rpc_error(-32601, f"Method not found: {method}", _id)
        try:
            if params is None: params = {}
            if not isinstance(params, dict): return rpc_error(-32602, "Invalid params: must be object", _id)
            result = await func(params)
            return rpc_result(result, _id)
        except ValueError as ve:
            return rpc_error(-32602, "Invalid params", _id, data=str(ve))
        except Exception as e:
            return rpc_error(-32603, "Internal error", _id, data=str(e))

    if isinstance(payload, list):
        res: List[Dict[str, Any]] = []
        for it in payload:
            r = await _handle(it)
            if r is not None: res.append(r)
        return res if res else None
    return await _handle(payload)

# ================== 路由 ==================
@router.post("/")
async def mcp_entry(body: Union[Dict[str, Any], List[Any]] = Body(...)):
    rid = str(uuid.uuid4())
    REQ_ID.set(rid)
    t0 = time.time()
    logj(logging.INFO, "rpc_in", body_type=type(body).__name__)
    resp = await handle_rpc_payload(body)
    elapsed = round(time.time() - t0, 3)
    if resp is None:
        logj(logging.INFO, "rpc_out", elapsed=elapsed, kind="notification")
        return Response(status_code=204)
    try:
        size = len(json.dumps(resp, ensure_ascii=False))
    except Exception:
        size = -1
    logj(logging.INFO, "rpc_out", elapsed=elapsed, size=size)
    return JSONResponse(content=resp)

@router.get("/")
async def root():
    return {"hint": "POST JSON-RPC 2.0 here: initialize, tools/list, tools/call.",
            "sse": "/jobs/{job_id}/sse", "health": "/health"}

@router.get("/health")
async def health():
    bins = {}
    for name, tool in TOOLS.items():
        if not tool.get("enabled", True): 
            continue
        b = tool.get("bin")
        ok = await which(b)
        bins[b] = ok if b not in bins else (bins[b] or ok)
    return {"status": "ok", "binaries": bins}

# 实时 SSE
@router.get("/jobs/{job_id}/sse")
async def job_sse(job_id: str = Path(...)):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error":"job not found"}, status_code=404)

    async def _gen():
        idx = 0
        yield "event: open\ndata: {}\n\n"
        while True:
            while idx < len(job.buffer):
                line = job.buffer[idx]
                yield f"data: {json.dumps({'line': line})}\n\n"
                idx += 1
            if job.done:
                yield f"event: end\ndata: {json.dumps({'rc': job.rc})}\n\n"
                break
            try:
                await asyncio.wait_for(job.event.wait(), timeout=15)
            except asyncio.TimeoutError:
                yield "event: keepalive\ndata: {}\n\n"
            finally:
                job.event.clear()
    return StreamingResponse(_gen(), media_type="text/event-stream")

# 长轮询
@router.get("/jobs/poll")
async def jobs_poll(job_id: str, cursor: int = 0):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error":"job not found"}, status_code=404)
    start = max(0, cursor - job.cursor0)
    lines = job.buffer[start:]
    next_cursor = job.cursor0 + len(job.buffer)
    return {"job_id": job_id, "done": job.done, "rc": job.rc, "cursor": next_cursor, "lines": lines}

@router.post("/jobs/cancel")
async def jobs_cancel(job_id: str = Body(..., embed=True)):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error":"job not found"}, status_code=404)
    if job.proc and not job.done:
        try:
            job.proc.terminate()
        except Exception:
            pass
        return {"ok": True}
    return {"ok": False, "message": "job already finished or no process"}

# 能力自描述（含 build 摘要）
_BIN_CACHE: Dict[str, Dict[str, Any]] = {}

@router.get("/capabilities_ext")
async def capabilities_ext():
    tools = []
    for name, tool in TOOLS.items():
        if not tool.get("enabled", True): 
            continue
        bin_name = tool.get("bin")
        if bin_name not in _BIN_CACHE:
            ok = await which(bin_name)
            ver = await _bin_version(bin_name) if ok else None
            _BIN_CACHE[bin_name] = {"available": ok, "version": ver}
        tools.append({
            "name": name,
            "description": tool.get("desc",""),
            "inputSchema": _params_to_jsonschema(tool.get("params", {})),
            "defaults": tool.get("defaults", {}),
            "binary": {"name": bin_name, **_BIN_CACHE[bin_name]},
            "build_summary": tool.get("build", [])[:5]  # 仅展示前几项作摘要
        })
    return {
        "server": {"ignore_timeout": IGNORE_TIMEOUT, "default_timeout": DEFAULT_TIMEOUT,
                   "hard_timeout_cap_sec": HARD_TIMEOUT_CAP, "max_concurrent_jobs": MAX_CONCUR},
        "assets": {"port_profiles": cfg("assets.port_profiles", {})},
        "tools": tools
    }

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT","8080")))
