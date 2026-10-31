"""Exception types. All load-time errors subclass PolicyError."""


class PolicyError(Exception):
    """Base class for every load-time policy error."""


class PolicySyntaxError(PolicyError):
    """The policy JSON or one of its expressions is outside the DSL (SPEC section 2, 2.1)."""


class InitViolation(PolicyError):
    """The initial state violates one or more invariants."""

    def __init__(self, invariants):
        self.invariants = list(invariants)
        super().__init__(f"init violates invariants: {', '.join(self.invariants)}")


class PolicyNotInductive(PolicyError):
    """Some action does not preserve some invariant (or the solver could not decide)."""

    def __init__(self, action, invariant, counterexample):
        self.action = action
        self.invariant = invariant
        self.counterexample = counterexample
        what = "counterexample " + repr(counterexample) if counterexample is not None else "solver returned unknown"
        super().__init__(f"action {action!r} does not preserve invariant {invariant!r}: {what}")


class ReceiptInvalid(Exception):
    """A receipt failed structural or signature verification."""
