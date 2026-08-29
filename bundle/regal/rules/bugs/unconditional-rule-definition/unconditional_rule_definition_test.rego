package regal.rules.bugs["unconditional-rule-definition_test"]

import data.regal.ast

import data.regal.rules.bugs["unconditional-rule-definition"] as rule

# The shape of the violation, asserted once in full. The remaining tests assert
# which definition was flagged, which is the part that can actually regress.
test_fail_catch_all_with_conflicting_value if {
	r := rule.report with input as ast.policy(`
	allow := true if input.ok

	allow := false
	`)

	r == {{
		"category": "bugs",
		"description": "Rule defined unconditionally alongside conditional definitions",
		"level": "error",
		"location": {
			"col": 2,
			"end": {
				"col": 16,
				"row": 6,
			},
			"file": "policy.rego",
			"row": 6,
			"text": "\tallow := false",
		},
		"related_resources": [{
			"description": "documentation",
			"ref": "https://www.openpolicyagent.org/projects/regal/rules/bugs/unconditional-rule-definition",
		}],
		"title": "unconditional-rule-definition",
	}}
}

# The catch-all agrees with the conditional definition, so evaluation does not
# fail. The conditional definition is dead code, which is still worth reporting.
test_fail_catch_all_with_same_value if {
	r := rule.report with input as ast.policy(`
	deny := true if input.bad

	deny := true
	`)

	_flagged(r) == {"\tdeny := true"}
}

# The function form, which is the one that turns up in practice.
test_fail_catch_all_function if {
	r := rule.report with input as ast.policy(`
	f(x) if x > 10

	f(_) := false
	`)

	_flagged(r) == {"\tf(_) := false"}
}

test_fail_catch_all_alongside_default if {
	r := rule.report with input as ast.policy(`
	default f(_) := false

	f(x) if x > 10

	f(_) := false
	`)

	_flagged(r) == {"\tf(_) := false"}
}

test_fail_catch_all_before_the_conditional_definition if {
	r := rule.report with input as ast.policy(`
	allow := false

	allow := true if input.ok
	`)

	_flagged(r) == {"\tallow := false"}
}

test_fail_catch_all_with_constant_composite_value if {
	r := rule.report with input as ast.policy(`
	config := {"mode": "strict"} if input.strict

	config := {"mode": "loose"}
	`)

	_flagged(r) == {"\tconfig := {\"mode\": \"loose\"}"}
}

test_fail_two_catch_alls_are_both_reported if {
	r := rule.report with input as ast.policy(`
	allow := true if input.ok

	allow := false

	allow := true
	`)

	_flagged(r) == {"\tallow := false", "\tallow := true"}
}

test_fail_partial_object_rule_with_static_ref if {
	r := rule.report with input as ast.policy(`
	config.mode := "strict" if input.strict

	config.mode := "loose"
	`)

	_flagged(r) == {"\tconfig.mode := \"loose\""}
}

# --- cases that must not be reported ----------------------------------------

# `contains` definitions union rather than conflict, so an unconditional one
# says nothing about whether the others matter.
test_success_multi_value_rule if {
	r := rule.report with input as ast.policy(`
	deny contains "always"

	deny contains msg if {
		msg := "sometimes"
	}
	`)

	r == set()
}

# `f("a")` has no body but applies only to that one argument, so the other
# definitions in the set still do the work for every other argument.
test_success_function_with_constant_argument if {
	r := rule.report with input as ast.policy(`
	f("a") := 1

	f(x) := 2 if x == "b"
	`)

	r == set()
}

# Repeating an argument name is a constraint, not a catch-all: this matches
# only calls where both arguments are equal.
test_success_function_with_repeated_argument_name if {
	r := rule.report with input as ast.policy(`
	f(x, x) := 1

	f(x, y) := 2 if x != y
	`)

	r == set()
}

# The unconditional definition can itself be undefined, so the conditional one
# is what answers in that case. Reporting this would be a false positive.
test_success_unconditional_value_is_not_constant if {
	r := rule.report with input as ast.policy(`
	allow := input.override

	allow := false if not input.override
	`)

	r == set()
}

test_success_default_and_one_conditional_definition if {
	r := rule.report with input as ast.policy(`
	default allow := false

	allow := true if input.ok
	`)

	r == set()
}

test_success_only_unconditional_definitions if {
	r := rule.report with input as ast.policy(`
	allow := false
	`)

	r == set()
}

test_success_all_definitions_conditional if {
	r := rule.report with input as ast.policy(`
	allow := true if input.ok

	allow := false if input.blocked
	`)

	r == set()
}

# `else` is one way to write a fallback, `default` another. It is a single rule
# with an ordered chain rather than a set of definitions, so the earlier
# conditions do decide the answer and there is nothing to report.
test_success_else_fallback if {
	r := rule.report with input as ast.policy(`
	f(x) := 1 if {
		x > 10
	} else := 2
	`)

	r == set()
}

test_success_different_rules_do_not_pair_up if {
	r := rule.report with input as ast.policy(`
	allow := true if input.ok

	deny := false
	`)

	r == set()
}

_flagged(report) := {violation.location.text | some violation in report}
