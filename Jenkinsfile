#!groovy

@Library('cdis-jenkins-lib@refactor/microservices') _
// import uchicago.cdis.MicroservicePipeline

runPipeline {
  pipeline = 'microservice'
  service = 'fence'

  namespaces = [
    "jenkins-brain",
    "jenkins-niaid",
    "jenkins-dcp"
  ]

  skipDeploy = 'true'
}

// microservicePipeline2(config)

// import uchicago.cdis.*
// Map pipelineDefinition = [
//     myVariable: "hello world"
// ]
// testing 1234


// new MicroservicePipeline(this).execute()