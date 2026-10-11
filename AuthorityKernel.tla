---------------- MODULE AuthorityKernel ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Requests, Capabilities
ASSUME Requests # {} /\ Capabilities # {}

VARIABLES phase, hasCapability, policyOK, authenticated, approved, denied, executed, auditCreated, errorFlag
vars == <<phase, hasCapability, policyOK, authenticated, approved, denied, executed, auditCreated, errorFlag>>

Init ==
  /\ phase = [r \in Requests |-> "new"]
  /\ hasCapability = [r \in Requests |-> FALSE]
  /\ policyOK = [r \in Requests |-> FALSE]
  /\ authenticated = [r \in Requests |-> FALSE]
  /\ approved = [r \in Requests |-> FALSE]
  /\ denied = [r \in Requests |-> FALSE]
  /\ executed = [r \in Requests |-> FALSE]
  /\ auditCreated = [r \in Requests |-> FALSE]
  /\ errorFlag = [r \in Requests |-> FALSE]

Authenticate(r) ==
  /\ phase[r] = "new"
  /\ authenticated' = [authenticated EXCEPT ![r] = TRUE]
  /\ phase' = [phase EXCEPT ![r] = "authenticated"]
  /\ UNCHANGED <<hasCapability, policyOK, approved, denied, executed, auditCreated, errorFlag>>

EvaluatePolicy(r, allowed) ==
  /\ phase[r] = "authenticated"
  /\ policyOK' = [policyOK EXCEPT ![r] = allowed]
  /\ phase' = [phase EXCEPT ![r] = "evaluated"]
  /\ UNCHANGED <<hasCapability, authenticated, approved, denied, executed, auditCreated, errorFlag>>

ValidateCapability(r, valid) ==
  /\ phase[r] = "evaluated"
  /\ hasCapability' = [hasCapability EXCEPT ![r] = valid]
  /\ phase' = [phase EXCEPT ![r] = "capability_checked"]
  /\ UNCHANGED <<policyOK, authenticated, approved, denied, executed, auditCreated, errorFlag>>

Approve(r, value) ==
  /\ phase[r] = "capability_checked"
  /\ approved' = [approved EXCEPT ![r] = value]
  /\ phase' = [phase EXCEPT ![r] = "approval_checked"]
  /\ UNCHANGED <<hasCapability, policyOK, authenticated, denied, executed, auditCreated, errorFlag>>

Execute(r) ==
  /\ phase[r] \in {"capability_checked", "approval_checked"}
  /\ authenticated[r] = TRUE
  /\ policyOK[r] = TRUE
  /\ hasCapability[r] = TRUE
  /\ (phase[r] = "capability_checked" \/ approved[r] = TRUE)
  /\ errorFlag[r] = FALSE
  /\ executed' = [executed EXCEPT ![r] = TRUE]
  /\ auditCreated' = [auditCreated EXCEPT ![r] = TRUE]
  /\ phase' = [phase EXCEPT ![r] = "done"]
  /\ UNCHANGED <<hasCapability, policyOK, authenticated, approved, denied, errorFlag>>

Deny(r) ==
  /\ phase[r] \in {"authenticated", "evaluated", "capability_checked", "approval_checked"}
  /\ (errorFlag[r] \/ ~authenticated[r] \/ ~policyOK[r] \/ ~hasCapability[r] \/ (phase[r] = "approval_checked" /\ ~approved[r]))
  /\ denied' = [denied EXCEPT ![r] = TRUE]
  /\ auditCreated' = [auditCreated EXCEPT ![r] = TRUE]
  /\ phase' = [phase EXCEPT ![r] = "done"]
  /\ UNCHANGED <<hasCapability, policyOK, authenticated, approved, executed, errorFlag>>

SetError(r) ==
  /\ phase[r] # "done"
  /\ errorFlag' = [errorFlag EXCEPT ![r] = TRUE]
  /\ UNCHANGED <<phase, hasCapability, policyOK, authenticated, approved, denied, executed, auditCreated>>

Next == \E r \in Requests:
  Authenticate(r) \/ EvaluatePolicy(r, TRUE) \/ EvaluatePolicy(r, FALSE) \/
  ValidateCapability(r, TRUE) \/ ValidateCapability(r, FALSE) \/
  Approve(r, TRUE) \/ Approve(r, FALSE) \/ Execute(r) \/ Deny(r) \/ SetError(r)

TypeOK ==
  /\ phase \in [Requests -> {"new", "authenticated", "evaluated", "capability_checked", "approval_checked", "done"}]
  /\ hasCapability \in [Requests -> BOOLEAN]
  /\ policyOK \in [Requests -> BOOLEAN]
  /\ authenticated \in [Requests -> BOOLEAN]
  /\ approved \in [Requests -> BOOLEAN]
  /\ denied \in [Requests -> BOOLEAN]
  /\ executed \in [Requests -> BOOLEAN]
  /\ auditCreated \in [Requests -> BOOLEAN]
  /\ errorFlag \in [Requests -> BOOLEAN]

NoExecutionWithoutAuthorization ==
  \A r \in Requests: executed[r] => authenticated[r] /\ policyOK[r] /\ hasCapability[r] /\ auditCreated[r]

NoExecuteAndDeny == \A r \in Requests: ~(executed[r] /\ denied[r])

ErrorDoesNotExecute == \A r \in Requests: errorFlag[r] => ~executed[r]

Spec == Init /\ [][Next]_vars

===========================================================
