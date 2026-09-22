# source: infra-commons@<ref> hcl/single-source/role-inert-output.tf
# class: single-source
# proven-in: 1 consumer (two roles, two worktrees, one module), last 2026-09-22
# caveats: `role` is a FACT line, not a switch — nothing inside the module may
#   branch on it (no `count = var.role == ...`); role-conditional resources are
#   count-gated on their OWN inputs (a mail domain being non-empty, a second
#   hostname being set), so a role with those inputs empty simply has fewer
#   resources; the deploy scripts read the role from the facts cache the
#   wrapper writes after every run (0600, gitignored) and must default to the
#   primary role while the output is absent from an older state.

variable "role" {
  type        = string
  default     = "app"
  description = "What this instance is: \"app\" (the primary role) or \"staging\" (a second role with its own worktree, tfvars and state). Inert inside this module — exported as an output so the deploy scripts pick the matching legs."
  validation {
    condition     = contains(["app", "staging"], var.role)
    error_message = "role must be \"app\" or \"staging\"."
  }
}

output "role" {
  value       = var.role
  description = "Instance role. Read by the deploy scripts through the facts cache; absent from state until the next apply, so they must default to \"app\"."
}
