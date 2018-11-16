#!groovy

@Library('cdis-jenkins-lib@refactor/microservices') _
// import uchicago.cdis.MicroservicePipeline

runPipeline {
  pipeline = 'microservice'

  namespaces = [
    "jenkins-brain",
    "jenkins-niaid",
    "jenkins-dcp"
  ]

  skipDeploy = 'true'
}

// import uchicago.cdis.*
// Map pipelineDefinition = [
//     myVariable: "hello world"
// ]


// new MicroservicePipeline(this).execute()