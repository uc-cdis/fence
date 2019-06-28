workflow "Run python formatter" {
  on = "pull_request"
  resolves = ["Run wool"]
}

action "Run wool" {
  uses = "uc-cdis/wool@master"
  secrets = ["GITHUB_TOKEN"]
}
