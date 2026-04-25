"""
Kill chain detector for FedGate.

Tracks hashed session identifiers across API gateway nodes.
Detects the Login→Payment→Admin account-takeover kill chain
within a configurable time window.

Privacy model: only hashed session IDs and timestamps leave each node.
No raw request data, payloads, credentials, or user identifiers are shared.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional


KILL_CHAIN_SEQUENCE = [0, 1, 4]   # Login → Payment → Admin (node IDs)
KILL_CHAIN_WINDOW   = 180          # seconds

NODE_NAMES = {0: 'Login', 1: 'Payment', 2: 'Search', 3: 'Profile', 4: 'Admin'}


class KillChainDetector:
    """
    In-memory session correlation engine.

    Each node calls record_event() with a hashed session identifier.
    After every record, _check_kill_chain() tests whether the
    KILL_CHAIN_SEQUENCE has appeared in order within the time window.
    """

    def __init__(self, window_seconds: int = KILL_CHAIN_WINDOW):
        self.window = window_seconds
        self._sessions: dict[str, list[dict]] = defaultdict(list)

    def record_event(
        self,
        session_hash: str,
        node_id: int,
        event_type: str,
        timestamp: Optional[datetime] = None,
    ) -> Optional[dict]:
        """Record a session event. Returns kill chain alert dict if chain detected, else None."""
        now = timestamp or datetime.utcnow()
        self._sessions[session_hash].append({
            'node_id':    node_id,
            'event_type': event_type,
            'timestamp':  now,
        })
        self._prune(session_hash, now)
        return self._check_kill_chain(session_hash)

    def _prune(self, session_hash: str, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window)
        self._sessions[session_hash] = [
            e for e in self._sessions[session_hash] if e['timestamp'] > cutoff
        ]

    def _check_kill_chain(self, session_hash: str) -> Optional[dict]:
        events = self._sessions[session_hash]
        found_indices: list[int] = []
        search_from = 0
        for target_node in KILL_CHAIN_SEQUENCE:
            for idx in range(search_from, len(events)):
                if events[idx]['node_id'] == target_node:
                    found_indices.append(idx)
                    search_from = idx + 1
                    break
        if len(found_indices) < len(KILL_CHAIN_SEQUENCE):
            return None
        chain_events = [events[i] for i in found_indices]
        elapsed = (chain_events[-1]['timestamp'] - chain_events[0]['timestamp']).total_seconds()
        return {
            'alert':          'KILL_CHAIN_DETECTED',
            'session':        session_hash,
            'chain':          [NODE_NAMES[e['node_id']] for e in chain_events],
            'chain_node_ids': [e['node_id'] for e in chain_events],
            'elapsed_seconds': round(elapsed, 1),
        }

    def reset(self) -> None:
        self._sessions.clear()


def generate_demo_scenario() -> dict:
    """Return the scripted kill chain demo scenario (used by /kill-chain-demo endpoint)."""
    session_id = 'session_7f3a'
    return {
        'session':  session_id,
        'scenario': 'account_takeover_kill_chain',
        'description': (
            'Three-stage account takeover: credential test → payment probe → admin enumeration. '
            'Each stage hits a different node, spaced 60–90 s apart at a rate of 1 request per node. '
            'No individual node sees anything unusual. '
            'The kill chain is only visible in the federation layer.'
        ),
        'events': [
            {
                'step':            1,
                'sim_elapsed_s':   0,
                'sim_time_label':  'T+0s',
                'node_id':         0,
                'node_name':       'Login',
                'event_type':      'AUTH_SUCCESS',
                'endpoint':        '/api/login',
                'code':            200,
                'session':         session_id,
                'local_flag':      False,
                'note':            '1 successful login — indistinguishable from normal user activity',
            },
            {
                'step':            2,
                'sim_elapsed_s':   60,
                'sim_time_label':  'T+60s',
                'node_id':         1,
                'node_name':       'Payment',
                'event_type':      'PAYMENT_PROBE',
                'endpoint':        '/api/payment/confirm',
                'code':            200,
                'session':         session_id,
                'local_flag':      False,
                'note':            '1 payment request from same session — looks like a normal purchase',
            },
            {
                'step':            3,
                'sim_elapsed_s':   127,
                'sim_time_label':  'T+2m7s',
                'node_id':         4,
                'node_name':       'Admin',
                'event_type':      'ADMIN_PROBE',
                'endpoint':        '/api/admin/config',
                'code':            403,
                'session':         session_id,
                'local_flag':      False,
                'note':            '1 admin probe — looks like a mis-click locally, no local alert fires',
            },
        ],
        'alert': {
            'type':             'KILL_CHAIN_DETECTED',
            'session':          session_id,
            'chain':            'Login → Payment → Admin',
            'chain_node_ids':   [0, 1, 4],
            'elapsed_seconds':  127,
            'signal': (
                'Session hash federated alongside model weights via CKKS-encrypted channel. '
                'Kill chain is visible only in the federation layer — '
                'no single node had sufficient context to flag it alone.'
            ),
            'privacy_note': (
                'No raw session data left any node. Only the hashed session identifier and '
                'a timestamp were federated. Raw API logs, credentials, and payloads stayed local.'
            ),
        },
    }
