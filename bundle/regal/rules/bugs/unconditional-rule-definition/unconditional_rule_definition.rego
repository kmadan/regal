# METADATA
# description: Rule defined unconditionally alongside conditional definitions
# related_resources:
#   - description: documentation
#     ref: https://www.openpolicyagent.org/projects/regal/rules/bugs/unconditional-rule-definition
package regal.rules.bugs["unconditional-rule-definition"]

import data.regal.ast
import data.regal.result

report contains violation if {
	some name, definitions in _single_value_definitions

	# At least one definition decides its value based on conditions...
	_names_with_a_conditional_definition[name]

	# ...and at least one is always defined, whatever the input. The conditions
	# above can then never decide the answer: either the two values differ and
	# evaluation fails with a conflict, or they agree and the conditional
	# definition is dead code.
	some unconditional in definitions
	_always_defined(unconditional)

	violation := result.fail(rego.metadata.chain(), result.location(unconditional))
}

# Names carrying at least one conditional definition.
#
# Pairing the two kinds by iterating both inside `report` walks the definitions
# of a name once per conditional definition it has, to reach a violation that
# depends only on the unconditional one. Collecting the names first makes the
# pairing a single set lookup.
_names_with_a_conditional_definition contains name if {
	some name, definitions in _single_value_definitions
	some rule in definitions

	_condition_count(rule) > 0
}

# Definitions of single-value rules, grouped by the name they define.
#
# Multi-value rules (`deny contains msg if ...`) are excluded, as their
# definitions union rather than conflict — an unconditional `deny contains "x"`
# says nothing about whether the other definitions matter. Refs with variable
# parts (`p[x] := v`) generate a collection for the same reason.
_single_value_definitions[name] contains rule if {
	some rule in input.rules

	not rule.default

	# A head with a key and no value is multi-value. Testing for the key alone
	# would be wrong: a ref-head rule like `config.mode := "loose"` also carries
	# a key, which is only the last part of its ref, and it is single-value.
	rule.head.value

	_static_ref(rule.head.ref)

	name := ast.ref_to_string(rule.head.ref)
}

# How many conditions a definition carries.
#
# `body` is absent altogether on a definition written without `if`, rather than
# present and empty, and an absent key makes `count` undefined rather than zero.
# The default here is what keeps that from quietly failing every comparison —
# the same "undefined is not false" trap this rule exists to catch.
_condition_count(rule) := count(object.get(rule, "body", []))

# `ast.static_ref` takes a term rather than a bare ref, and a rule head's `ref`
# is the array itself. `ast.ref_static_to_string` truncates a ref at its first
# non-static part, and that truncation is a no-op exactly when the ref is
# static, so comparing the two string forms is the same test without a shim.
_static_ref(ref) if ast.ref_static_to_string(ref) == ast.ref_to_string(ref)

_always_defined(rule) if {
	_condition_count(rule) == 0
	not rule["else"]

	# A non-constant value can itself be undefined, and then the conditional
	# definitions are not pointless at all: in
	#
	#   allow := input.override
	#   allow := false if not input.override
	#
	# the second definition is what answers when the first is undefined.
	ast.is_constant(rule.head.value)

	_matches_any_arguments(rule)
}

# Rules that are not functions take no arguments, so nothing further to check.
_matches_any_arguments(rule) if not rule.head.args

# A function definition only catches everything when every argument is a
# distinct variable. `f("a") := 1` has no body, but applies only to the argument
# "a", so it leaves the other definitions in the set doing real work. Repeating
# a name — `f(x, x)` — is a constraint too, so the names must be distinct.
_matches_any_arguments(rule) if {
	every arg in rule.head.args {
		arg.type == "var"
	}

	count({arg.value | some arg in rule.head.args}) == count(rule.head.args)
}
