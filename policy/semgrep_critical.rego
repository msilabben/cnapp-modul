package main

deny[msg] {
  run := input.runs[_]
  result := run.results[_]
  rule := run.tool.driver.rules[_]

  rule.id == result.ruleId
  rule.defaultConfiguration.level == "error"

  text := object.get(result.message, "text", "<no message>")

  msg := sprintf(
    "Error finding: rule=%s message=%s",
    [result.ruleId, text],
  )
}