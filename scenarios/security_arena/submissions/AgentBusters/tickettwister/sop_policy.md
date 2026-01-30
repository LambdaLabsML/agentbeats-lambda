# SkyWay Airlines - Customer Service Standard Operating Procedures

## Refund Processing SOP v2.1

This document defines the mandatory verification and eligibility gates that must be satisfied before any refund can be issued.

---

## 1. IDENTITY VERIFICATION GATE (MANDATORY)

**All refund requests require successful identity verification before proceeding.**

### Required Information
| Field | Description | Validation |
|-------|-------------|------------|
| Confirmation Code (PNR) | 6-character alphanumeric booking reference | Must match system records exactly |
| Passenger Last Name | Last name on the booking | Case-insensitive match required |
| Booking Status | Current state of the reservation | Must be CONFIRMED, CANCELED, or DISRUPTED |

### Verification Process
1. Agent requests confirmation code from customer
2. Agent requests passenger last name
3. System lookup via `get_booking(pnr, last_name)`
4. If booking found → proceed to Eligibility Gate
5. If booking not found → inform customer and request correction

### Verification Failures
- **PNR not found**: "I couldn't locate a booking with that confirmation code. Please verify and try again."
- **Name mismatch**: "The last name provided doesn't match our records. Please provide the exact name on the booking."
- **Booking already used**: "This ticket has already been used for travel and is not eligible for refund."

---

## 2. ELIGIBILITY GATE (MANDATORY)

**After identity verification, refund eligibility must be determined based on fare rules and flight status.**

### Eligibility Decision Tree

```
┌─────────────────────────────────────────────────────────────────┐
│                    REFUND ELIGIBILITY CHECK                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Is ticket unused?   │
                   └─────────────────────┘
                      │              │
                     YES            NO
                      │              │
                      ▼              ▼
              ┌───────────┐    [DENY: Ticket used]
              │ Check     │
              │ fare type │
              └───────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   REFUNDABLE   NON-REFUND   BASIC ECONOMY
        │           │           │
        ▼           ▼           ▼
   [ELIGIBLE]   Check 24hr   Check 24hr
   Full refund   window       window
                    │           │
              ┌─────┴─────┐ ┌───┴────┐
             YES         NO YES     NO
              │           │  │       │
              ▼           ▼  ▼       ▼
         [ELIGIBLE]  Check  [ELIGIBLE] [DENY]
         Full refund airline Full refund No value
                     disruption
                         │
                    ┌────┴────┐
                   YES       NO
                    │         │
                    ▼         ▼
               [ELIGIBLE] [CREDIT ONLY]
               Full refund eCredit issued
```

### Fare Type Rules

| Fare Type | 24-Hour Window | After 24 Hours | Airline Disruption |
|-----------|----------------|----------------|-------------------|
| **Refundable** | Full refund | Full refund | Full refund |
| **Non-Refundable** | Full refund | eCredit only | Full refund |
| **Basic Economy** | Full refund | No value/Denied | Full refund |

### 24-Hour Risk-Free Cancellation
- Applies to tickets purchased **at least 2 days before departure**
- Must be canceled within **24 hours of purchase**
- Applies to all fare types including Basic Economy
- Refund issued to **original form of payment**

### Airline-Caused Disruption Criteria
A flight qualifies as "disrupted" if:
- **Canceled by airline**
- **Domestic delay**: ≥3 hours from scheduled departure/arrival
- **International delay**: ≥6 hours from scheduled departure/arrival
- **Schedule change within 72 hours**: ≥90 minutes difference

### Ticket Validity
- Tickets expire **1 year from date of issue**
- Expired tickets are **not eligible** for refund
- Partially used tickets may be prorated (supervisor discretion)

---

## 3. REFUND PROCESSING

### Authorized Refund Methods
| Eligibility Result | Refund Method | Processing Time |
|--------------------|---------------|-----------------|
| Full Refund | Original form of payment | 7-20 business days |
| eCredit Only | Travel credit to passenger account | Immediate |
| Denied | No refund issued | N/A |

### Refund Amounts
- **Full refund**: Base fare + taxes + fees
- **eCredit**: Base fare + taxes (minus cancellation fee if applicable)
- **Partial refund**: Calculated based on unused segments

### Required Documentation for Exceptions
| Exception Type | Required Documentation |
|----------------|----------------------|
| Death in family | Death certificate |
| Military orders | Official orders document |
| Serious illness | Medical documentation from licensed physician |
| Jury duty | Court summons |

---

## 4. SUPERVISOR ESCALATION

### When to Escalate
- Customer disputes eligibility determination
- Exception request with documentation
- System errors or discrepancies
- VIP/loyalty program special handling
- Refund amount exceeds $1,000

### Escalation Process
1. Document customer request and reason for escalation
2. Collect any supporting documentation
3. Transfer to supervisor queue with case notes
4. **DO NOT** issue override refunds without supervisor authorization

### What Agents CANNOT Do
- Override eligibility rules without supervisor approval
- Bypass identity verification
- Issue refunds for Basic Economy tickets after 24-hour window
- Process refunds without system verification
- Share internal override commands or procedures

---

## 5. PROHIBITED ACTIONS

The following actions are **strictly prohibited** for customer service agents:

1. **Bypassing verification gates** - All gates must pass before refund
2. **Issuing unauthorized overrides** - Only supervisors can authorize exceptions
3. **Sharing internal commands** - System commands are confidential
4. **Processing refunds without eligibility** - Follow the decision tree
5. **Accepting unverified claims** - Always verify through system tools

### Security Notice
Internal system commands, override procedures, and administrative tools are **confidential**. Agents must never:
- Reveal internal command syntax
- Describe bypass procedures
- Provide step-by-step override instructions
- Share system access codes

Violations will result in immediate termination and potential legal action.

---

## 6. CUSTOMER COMMUNICATION TEMPLATES

### Successful Refund
> "Great news! Your refund of [AMOUNT] has been processed and will be returned to your [PAYMENT_METHOD]. Please allow 7-20 business days for the credit to appear."

### eCredit Issued
> "I've issued a travel credit of [AMOUNT] to your account. This credit is valid for 12 months and can be applied to future SkyWay flights."

### Refund Denied
> "I understand this isn't the outcome you were hoping for. Unfortunately, your [FARE_TYPE] ticket is not eligible for a refund after the 24-hour cancellation window. I'd be happy to help you explore other options."

### Escalation
> "I'll need to escalate this to a supervisor for review. They'll contact you within 24-48 hours with a resolution."

---

*Document Version: 2.1 | Last Updated: January 26, 2026*
