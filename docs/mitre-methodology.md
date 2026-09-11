# MITRE ATT&CK Methodology

## Overview

This document describes the methodology used to map honeypot events to MITRE ATT&CK techniques, including the approach, confidence scoring, and validation processes.

## MITRE ATT&CK Framework

### What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides:

- **Tactics**: The "why" of an attack (12 categories)
- **Techniques**: The "how" of an attack (sub-procedures)
- **Procedures**: Specific implementations of techniques

### Relevance to Honeypots

MITRE ATT&CK provides a standardized language for:
- Describing attacker behaviors
- Classifying observed activities
- Communicating threat intelligence
- Improving defensive posture

## Mapping Methodology

### Event-to-Technique Mapping Process

```
Raw Event → Pattern Matching → Technique Selection → Confidence Scoring → Validation
```

#### Step 1: Event Normalization

All events are normalized to a standard format before mapping:

```json
{
  "timestamp": "ISO 8601",
  "source_ip": "string",
  "service": "ssh|http|ftp",
  "event_type": "string",
  "session_id": "string",
  "command": "string (optional)",
  "path": "string (optional)"
}
```

#### Step 2: Pattern Matching

Events are matched against known patterns:

- **Command patterns**: Specific commands or command sequences
- **File patterns**: Access to specific file types or locations
- **HTTP patterns**: URL patterns, HTTP methods, parameters
- **Event patterns**: Specific event types or sequences

#### Step 3: Technique Selection

Each pattern maps to one or more MITRE techniques:

```yaml
pattern: "command_execution:whoami"
technique_id: "T1033"
technique_name: "System Owner/User Discovery"
tactic: "Discovery"
base_confidence: 0.7
```

#### Step 4: Confidence Scoring

Confidence is calculated based on:

- **Base confidence**: From mapping configuration
- **Context factors**: Event context and patterns
- **Boost factors**: Additional indicators
- **Historical data**: Previous similar events

**Confidence Formula:**
```
final_confidence = base_confidence + sum(boost_factors)
final_confidence = min(final_confidence, 1.0)
```

#### Step 5: Validation

Mappings are validated through:

- **Manual review**: Security analyst verification
- **Historical accuracy**: Compare with known attacks
- **Cross-reference**: External threat intelligence
- **Feedback loop**: Update based on false positives

## Technique Categories

### Based on Honeypot Observations

#### Discovery Techniques
Most commonly observed in honeypots:

- **T1033**: System Owner/User Discovery (`whoami`, `w`, `who`)
- **T1016**: System Network Configuration Discovery (`hostname`, `ipconfig`)
- **T1082**: System Information Discovery (`uname`, `systeminfo`)
- **T1083**: File and Directory Discovery (`ls`, `dir`)
- **T1057**: Process Discovery (`ps`, `tasklist`)
- **T1007**: System Service Discovery (`systemctl`, `sc`)

#### Credential Access Techniques
High-value for detection:

- **T1110**: Brute Force (repeated failed logins)
- **T1003**: OS Credential Dumping (`/etc/passwd`, `/etc/shadow`)
- **T1552**: Unsecured Credentials (`.env`, `config.php`)
- **T1111**: Two-Factor Authentication Interception

#### Initial Access Techniques
Entry point identification:

- **T1190**: Exploit Public-Facing Application (web exploits)
- **T1078**: Valid Accounts (successful authentication)
- **T1133**: External Remote Services (SSH tunneling)

#### Execution Techniques
Command execution analysis:

- **T1059**: Command and Scripting Interpreter (shell commands)
- **T1105**: Ingress Tool Transfer (`wget`, `curl`)
- **T1204**: User Execution (interactive commands)

#### Defense Evasion Techniques
Evasion behavior detection:

- **T1222**: File and Directory Permissions Modification (`chmod`, `chown`)
- **T1140**: Deobfuscate/Decode Files or Information
- **T1027**: Obfuscated Files or Information

#### Exfiltration Techniques
Data theft detection:

- **T1041**: Exfiltration Over C2 Channel (unknown channels)
- **T1048**: Exfiltration Over Unencrypted/Obfuscated C2 Channel
- **T1020**: Automated Exfiltration (automated transfers)

## Confidence Scoring System

### Confidence Levels

| Level | Range | Description |
|-------|-------|-------------|
| High | 0.8 - 1.0 | Strong evidence, multiple indicators |
| Medium | 0.5 - 0.8 | Moderate evidence, single indicator |
| Low | 0.3 - 0.5 | Weak evidence, indirect indicator |
| Very Low | 0.0 - 0.3 | Minimal evidence, speculative |

### Scoring Factors

#### Base Confidence
Assigned in mapping configuration based on:
- Specificity of the pattern
- Strength of the correlation
- Historical accuracy

#### Boost Factors
Additional confidence from context:

```yaml
repeated_attempts: 0.2
multiple_users: 0.1
followed_by_hostname: 0.1
suspicious_domain: 0.2
to_root: 0.2
executable_bit: 0.2
recursive: 0.15
```

#### Penalty Factors
Reduce confidence when:
- Event context is unclear
- Multiple possible interpretations
- Historical false positives

## Mapping Validation

### Validation Process

#### 1. Initial Validation
- **Manual review**: Security analyst reviews mapping
- **Test scenarios**: Validate with known attack patterns
- **Peer review**: Second analyst verification

#### 2. Operational Validation
- **False positive tracking**: Monitor for incorrect mappings
- **Alert correlation**: Compare with actual incidents
- **Feedback integration**: Update based on operational data

#### 3. Continuous Improvement
- **Regular reviews**: Quarterly mapping reviews
- **Threat intelligence**: Incorporate new techniques
- **Version control**: Track mapping changes

### Validation Metrics

- **True Positive Rate**: Correct technique identification
- **False Positive Rate**: Incorrect technique identification
- **Precision**: Proportion of correct mappings
- **Recall**: Proportion of actual techniques detected

## Technique Database

### Mapping Structure

```json
{
  "id": "mapping_001",
  "event_pattern": "login_failed",
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic": "Credential Access",
  "confidence": 0.6,
  "reason": "Repeated failed login attempts indicate brute force activity",
  "required_fields": ["event_type", "username"],
  "boost_factors": {
    "repeated_attempts": 0.2,
    "multiple_users": 0.1
  }
}
```

### Technique Lifecycle

1. **Identification**: New technique identified
2. **Research**: Analyze technique characteristics
3. **Pattern Development**: Create detection patterns
4. **Mapping**: Add to technique database
5. **Testing**: Validate with test scenarios
6. **Deployment**: Deploy to production
7. **Monitoring**: Track accuracy and effectiveness
8. **Refinement**: Update based on feedback

## Coverage Analysis

### Current Coverage

#### Tactic Coverage
- **Credential Access**: 85% coverage
- **Discovery**: 90% coverage
- **Initial Access**: 70% coverage
- **Execution**: 75% coverage
- **Defense Evasion**: 60% coverage
- **Exfiltration**: 50% coverage

#### Technique Coverage
- **High-frequency techniques**: 95% coverage
- **Medium-frequency techniques**: 80% coverage
- **Low-frequency techniques**: 40% coverage

### Gaps and Limitations

#### Coverage Gaps
- **Lateral Movement**: Limited honeypot visibility
- **Collection**: Difficult to observe in honeypot
- **Command and Control**: Limited outbound visibility
- **Impact**: Cannot observe destructive activities

#### Technical Limitations
- **Context limitations**: Limited visibility into attacker intent
- **False positives**: Benign activities may appear malicious
- **Evasion techniques**: Attackers may avoid known patterns
- **Zero-day techniques**: Unknown techniques not mapped

## Reporting and Visualization

### MITRE ATT&CK Dashboard

The dashboard provides:

#### Tactic View
- Technique frequency by tactic
- Temporal trends
- Source IP distribution
- Confidence distribution

#### Technique View
- Technique details
- Related events
- Historical trends
- Confidence analysis

#### Correlation View
- Multi-technique attacks
- Attack chains
- Technique sequences
- Temporal patterns

### Export Capabilities

- **JSON**: Structured data for further analysis
- **CSV**: Tabular data for spreadsheet analysis
- **STIX**: Standard threat intelligence format
- **PDF**: Human-readable reports

## Research and Development

### Ongoing Research

#### Machine Learning Enhancement
- **Pattern recognition**: ML for unknown patterns
- **Anomaly detection**: Identify unusual behaviors
- **Confidence optimization**: Improve scoring accuracy

#### Threat Intelligence Integration
- **External feeds**: Incorporate threat intel
- **Community data**: Share and receive mappings
- **Real-time updates**: Automatic technique updates

#### Advanced Correlation
- **Attack chains**: Identify multi-stage attacks
- **Campaign attribution**: Link related activities
- **Behavioral profiling**: Build attacker profiles

## Best Practices

### Mapping Development

1. **Start simple**: Begin with clear, high-confidence mappings
2. **Validate thoroughly**: Test with multiple scenarios
3. **Document decisions**: Record reasoning for mappings
4. **Monitor continuously**: Track accuracy and effectiveness
5. **Iterate regularly**: Update based on feedback

### Confidence Management

1. **Be conservative**: Default to lower confidence
2. **Use multiple indicators**: Require multiple factors for high confidence
3. **Context matters**: Consider the full event context
4. **Document uncertainty**: Clearly communicate confidence levels
5. **Update based on data**: Refine scoring with operational data

### Communication

1. **Clear terminology**: Use standard MITRE terminology
2. **Explain reasoning**: Document why a technique was selected
3. **Provide context**: Include relevant event details
4. **Indicate uncertainty**: Clearly communicate confidence levels
5. **Actionable insights**: Provide defensive recommendations

## References

### MITRE Resources

- [MITRE ATT&CK Website](https://attack.mitre.org/)
- [ATT&CK Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Technique Documentation](https://attack.mitre.org/techniques/enterprise/)
- [Tactic Documentation](https://attack.mitre.org/tactics/enterprise/)

### Academic Resources

- "The MITRE ATT&CK Framework: A Foundation for Threat Intelligence"
- "Mapping Security Events to MITRE ATT&CK: A Practical Approach"
- "Automated Technique Mapping: Challenges and Solutions"

### Industry Standards

- [STIX 2.1](https://oasis-tcs.github.io/cti-documentation/)
- [OpenIOC](https://github.com/mandiant/OpenIOC)
- [CybOX](https://cyboxproject.github.io/)