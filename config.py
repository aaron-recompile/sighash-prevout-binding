"""
RPC helpers for a local Bitcoin Inquisition signet node (via bitcoin-cli).

Environment:
  INQUISITION_DATADIR   node datadir (required)
  BITCOIN_CLI           bitcoin-cli binary (default: bitcoin-cli)
  INQUISITION_RPC_PORT  optional -rpcport
  INQUISITION_WALLET    funded wallet name (default: lab)
"""
import json
import subprocess
import os

RPC_DATADIR = os.environ.get("INQUISITION_DATADIR", "")
CLI_PATH = os.environ.get("BITCOIN_CLI", "bitcoin-cli")
RPC_PORT = os.environ.get("INQUISITION_RPC_PORT", "")
WALLET = os.environ.get("INQUISITION_WALLET", "lab")


def _check_config():
    if not RPC_DATADIR:
        raise ValueError(
            "Set INQUISITION_DATADIR (path to your Inquisition node datadir). "
            "Example: export INQUISITION_DATADIR=/path/to/inquisition-data"
        )


def _rpc_cmd_base():
    cmd = [CLI_PATH, "-signet", f"-datadir={RPC_DATADIR}"]
    if RPC_PORT:
        cmd.append(f"-rpcport={RPC_PORT}")
    return cmd


def rpc(method, *params):
    _check_config()
    cmd = _rpc_cmd_base() + [method]
    for p in params:
        if isinstance(p, (dict, list, bool, type(None))):
            cmd.append(json.dumps(p))
        else:
            cmd.append(str(p))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"RPC error: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()


def rpc_wallet(method, *params, wallet=None):
    wallet = wallet or WALLET
    _check_config()
    cmd = _rpc_cmd_base() + [f"-rpcwallet={wallet}", method]
    for p in params:
        if isinstance(p, (dict, list, bool, type(None))):
            cmd.append(json.dumps(p))
        else:
            cmd.append(str(p))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"RPC error: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()
