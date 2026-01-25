# Anomaly Detection

Sentinel can automatically detect unusual patterns without explicit rules.

## Overview

Traditional rule-based systems require you to anticipate every bad scenario. Anomaly detection learns what "normal" looks like and flags deviations.

```
Normal: $50, $60, $70, $80, $90
Anomaly: $5,000 ← 312 standard deviations from mean
```

## Enabling Anomaly Detection

```python
from sentinel import SentinelConfig

config = SentinelConfig(
    rules_path="rules.json",
    
    # Enable anomaly detection
    anomaly_detection=True,
    
    # Use statistical analysis (default, no cost)
    anomaly_statistical=True,
    
    # Use LLM analysis (optional, adds latency and cost)
    anomaly_llm=False,
    
    # Risk score thresholds
    anomaly_escalation_threshold=7.0,  # Force approval if >= 7
    anomaly_block_threshold=9.0,       # Auto-block if >= 9
)
```

## How It Works

### Statistical Detection (Default)

Uses Z-Score analysis on historical data:

1. **Collects baseline**: Reads audit logs to build history
2. **Calculates statistics**: Mean and standard deviation per parameter
3. **Computes Z-Score**: How many standard deviations from normal?
4. **Assigns risk**: Higher Z-Score = higher risk

```
Z-Score Formula: (value - mean) / standard_deviation

Example:
- Historical amounts: [50, 60, 70, 80, 90]
- Mean: 70
- Std Dev: 15.81
- New value: 5000
- Z-Score: (5000 - 70) / 15.81 = 311.8
```

### What It Detects

| Anomaly Type | Example |
|--------------|---------|
| **Value outliers** | Transfer of $5000 when average is $70 |
| **Frequency spikes** | 100 calls/hour when average is 5/hour |
| **New destinations** | Email to domain never seen before |
| **Unusual timing** | Activity at 3 AM when agent only runs 9-5 |

### Risk Levels

| Score | Level | Behavior |
|-------|-------|----------|
| 0-3 | LOW | Allow (no action) |
| 4-6 | MEDIUM | Log warning |
| 7-8 | HIGH | Force approval (even without rule) |
| 9-10 | CRITICAL | Block automatically |

## LLM Detection (Optional)

For semantic analysis beyond statistics:

```python
config = SentinelConfig(
    anomaly_detection=True,
    anomaly_llm=True,
    anomaly_llm_provider="openai",  # or "anthropic"
    anomaly_llm_model="gpt-4o-mini",
)
```

**Trade-offs:**
- ✅ Catches semantic anomalies ("email to competitor")
- ❌ Adds 500ms-2s latency
- ❌ Costs $0.001-0.01 per check
- ❌ Sends data to external API

**Recommendation:** Use statistical-only for most cases. Add LLM only for high-stakes actions.

## Building History

Anomaly detection needs history to work. It requires a minimum of 5 samples before it can detect anomalies.

```
Run 1: "Insufficient history (0 samples)"
Run 2: "Insufficient history (1 samples)"
...
Run 6: Anomaly detection active!
```

History comes from audit logs, so enable `audit_log=True`.

## Example Output

```
DEBUG - Loaded 5 historical events for transfer_funds
DEBUG - Param 'amount': current=5000.0, historical=[50, 60, 70, 80, 90]
DEBUG - Z-Score: value=5000.0, mean=70.00, stdev=15.81, z_score=311.80
INFO  - ANOMALY DETECTED: 'amount'=5000.0 (z-score=311.8, risk=10.0)
INFO  - Anomaly analysis: transfer_funds -> risk=10.0 (CRITICAL)

[BLOCKED] Anomaly detected (risk: 10.0): Parameter 'amount' is 311.8 
standard deviations from mean (70.00)
```

## Tuning Thresholds

### Conservative (Fintech, Healthcare)

```python
config = SentinelConfig(
    anomaly_escalation_threshold=5.0,  # Escalate sooner
    anomaly_block_threshold=7.0,       # Block sooner
)
```

### Permissive (Internal tools, Dev environments)

```python
config = SentinelConfig(
    anomaly_escalation_threshold=8.0,  # More tolerance
    anomaly_block_threshold=9.5,       # Only block extreme cases
)
```

## Combining with Rules

Anomaly detection works alongside rules, not replacing them:

```
Action → Check Rules → Check Anomalies → Decision

Example:
1. transfer_funds($500) called
2. Rules: "Amount > $100 requires approval" ✓
3. Anomalies: "Z-score = 2.1, risk = 5.0 (MEDIUM)" ✓
4. Decision: Require approval (rule matched)

Another example:
1. transfer_funds($50) called
2. Rules: No match (under $100)
3. Anomalies: "Z-score = 312, risk = 10.0 (CRITICAL)"
4. Decision: BLOCK (anomaly critical, even without rule)
```

## Best Practices

1. **Start with audit logging**: Build history before enabling detection
2. **Use statistical first**: Free, fast, no external dependencies
3. **Monitor false positives**: Adjust thresholds based on real data
4. **Add LLM for high-stakes**: Only where semantic analysis adds value
5. **Review anomaly logs**: Understand what your agents are actually doing
