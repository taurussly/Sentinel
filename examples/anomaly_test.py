"""Test script for Anomaly Detection."""

import asyncio
import logging
from pathlib import Path

from sentinel import SentinelConfig, SentinelBlockedError, protect

# Enable logging to see anomaly analysis output
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(name)s - %(message)s"
)
# Enable DEBUG for anomaly detector to see Z-score calculations
logging.getLogger("sentinel.anomaly").setLevel(logging.DEBUG)


def get_context():
    return {
        "current_balance": 5000.00,
        "account_status": "active",
    }


# Config COM anomaly detection ativado
config = SentinelConfig(
    rules_path=Path(__file__).parent.parent / "config" / "rules.json",
    approval_interface="terminal",
    agent_id="anomaly-test-agent",
    audit_log=True,
    
    # Anomaly Detection
    anomaly_detection=True,
    anomaly_statistical=True,
    anomaly_llm=False,  # Sem LLM por enquanto
    anomaly_escalation_threshold=7.0,
    anomaly_block_threshold=9.0,
)


@protect(config, context_fn=get_context)
async def transfer_funds(amount: float, destination: str) -> str:
    return f"Transferred ${amount} to {destination}"


async def main():
    print("=" * 60)
    print("Anomaly Detection Test")
    print("=" * 60)
    
    # Primeiro: Criar histórico "normal" (pequenas transferências)
    print("\n1. Creating baseline history (normal transfers)...")
    for i in range(5):
        try:
            result = await transfer_funds(50.0 + i*10, f"user{i}@example.com")
            print(f"   ${50 + i*10}: OK")
        except SentinelBlockedError as e:
            print(f"   Blocked: {e.reason}")
    
    print("\n2. Now attempting ANOMALOUS transfer ($5000)...")
    print("   (This is 100x larger than the baseline)")
    print("   Anomaly detection should flag this!\n")
    
    try:
        result = await transfer_funds(5000.0, "suspicious@example.com")
        print(f"[OK] SUCCESS: {result}")
        print("   (Anomaly detection may not have enough history yet)")
    except SentinelBlockedError as e:
        print(f"[BLOCKED] {e.reason}")
        if hasattr(e, 'risk_score'):
            print(f"   Risk Score: {e.risk_score}")

    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())