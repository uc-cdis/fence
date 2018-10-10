#!groovy

pipeline {
  agent any

  environment {
    QUAY_API = 'https://quay.io/api/v1/repository/cdis/'
  }

  stages {
    stage('FetchCode') {
      steps {
        dir('gen3-qa') {
          git(
            url: 'https://github.com/uc-cdis/gen3-qa.git',
            branch: 'fix/Jenkinsfile'
          )
        }
        dir('data-simulator') {
          git(
            url: 'https://github.com/occ-data/data-simulator.git',
            branch: 'master'
          )
        }
        dir('cdis-manifest') {
          git(
            url: 'https://github.com/uc-cdis/gitops-qa.git',
            branch: 'master'
          )
        }
        dir('cloud-automation') {
          git(
            url: 'https://github.com/uc-cdis/cloud-automation.git',
            branch: 'master'
          )
          script {
            env.GEN3_HOME=env.WORKSPACE+"/cloud-automation"
          }
        }
        dir('data-simulator') {
          git(
            url: 'https://github.com/occ-data/data-simulator.git',
            branch: 'master'
          )
        }
      }
    }
    stage('WaitForQuayBuild') {
      steps {
        script {
          service = "$env.JOB_NAME".split('/')[1]
          def timestamp = (("${currentBuild.timeInMillis}".substring(0, 10) as Integer) - 120)
          def timeout = (("${currentBuild.timeInMillis}".substring(0, 10) as Integer) + 3600)
          curlUrl = "$env.QUAY_API"+service+"/build/?since="+timestamp
          fullQuery = "curl -s "+curlUrl+/ | jq '.builds[] | "\(.tags[]),\(.display_name),\(.phase)"'/
          
          def testBool = false
          def allComplete = false

          while(testBool != true && allComplete != true) {
            allComplete = true
            currentTime = new Date().getTime()/1000 as Integer
            println "currentTime is: "+currentTime

            if(currentTime > timeout) {
              currentBuild.result = 'ABORTED'
              error("aborting build due to timeout")
            }

            sleep(30)

            resList = sh(script: fullQuery, returnStdout: true).trim().split('"\n"')
            println "Got quay result: " + resList.join("\n")

            for (String res in resList) {
              fields = res.replaceAll('"', "").split(',')
              //
              // if all pending builds are complete, then assume there's nothing to wait
              // for even if a build for our commit is not pending.
              // that can happen if someone re-runs a Jenkins job or whatever
              //
              if (fields.length > 2) {
                allComplete = allComplete && fields[2].endsWith("complete")
                if(fields[0].startsWith("$env.GIT_BRANCH".replaceAll("/", "_"))) {
                  if("$env.GIT_COMMIT".startsWith(fields[1])) {
                    testBool = fields[2].endsWith("complete")
                    break
                  } else {
                    currentBuild.result = 'ABORTED'
                    error("aborting build due to out of date git hash\npipeline: $env.GIT_COMMIT\nquay: "+fields[1])
                  }
                }
              }
            }
          }
        }
      }
    }
    stage('SelectNamespace') {
      steps {
        script {
          String[] namespaces = ['jenkins-brain']
          int modNum = namespaces.length/2
          int randNum = 0;  // always use bloodpac for now (new Random().nextInt(modNum) + ((env.EXECUTOR_NUMBER as Integer) * 2)) % namespaces.length

          if( ! env.KUBECTL_NAMESPACE ) {
            env.KUBECTL_NAMESPACE = namespaces[randNum];
          }
          println "selected namespace $env.KUBECTL_NAMESPACE on executor $env.EXECUTOR_NUMBER"

          println "attempting to lock namespace with a wait time of 5 minutes"
          uid = BUILD_TAG.replaceAll(' ', '_').replaceAll('%2F', '_')
          sh("bash cloud-automation/gen3/bin/klock.sh lock jenkins "+uid+" 3600 -w 300")
        }
      }
    }
    stage('ModifyManifest') {
      steps {
        script {
          dirname = sh(script: "kubectl -n $env.KUBECTL_NAMESPACE get configmap global -o jsonpath='{.data.hostname}'", returnStdout: true)
          service = "$env.JOB_NAME".split('/')[1]
          quaySuffix = "$env.GIT_BRANCH".replaceAll("/", "_")
        }
        dir("cdis-manifest/$dirname") {
          withEnv(["masterBranch=$service:master", "targetBranch=$service:$quaySuffix"]) {
            sh 'sed -i -e "s,'+"$env.masterBranch,$env.targetBranch"+',g" manifest.json'
          }
        }
      }
    }
    stage('K8sDeploy') {
      steps {
        withEnv(['GEN3_NOPROXY=true', "vpc_name=$env.KUBECTL_NAMESPACE", "GEN3_HOME=$env.WORKSPACE/cloud-automation"]) {
          echo "GEN3_HOME is $env.GEN3_HOME"
          echo "GIT_BRANCH is $env.GIT_BRANCH"
          echo "GIT_COMMIT is $env.GIT_COMMIT"
          echo "KUBECTL_NAMESPACE is $env.KUBECTL_NAMESPACE"
          echo "WORKSPACE is $env.WORKSPACE"
          sh "bash cloud-automation/gen3/bin/kube-roll-all.sh"
          sh "bash cloud-automation/gen3/bin/kube-wait4-pods.sh || true"
        }
      }
    }
    stage('RunTests') {
      steps {
        dir('gen3-qa') {
          withEnv(['GEN3_NOPROXY=true', "vpc_name=$env.KUBECTL_NAMESPACE", "NAMESPACE=$env.KUBECTL_NAMESPACE", "GEN3_HOME=$env.WORKSPACE/cloud-automation", , "TEST_DATA_PATH=$env.WORKSPACE/testData/"]) {
            sh "bash ./jenkins-simulate-data.sh $env.KUBECTL_NAMESPACE"
            sh "bash ./run-tests.sh $env.KUBECTL_NAMESPACE"
          }
        }
      }
    }
  }
  post {
    success {
      echo "https://jenkins.planx-pla.net/ $env.JOB_NAME pipeline succeeded"
    }
    failure {
      echo "Failure!"
      archiveArtifacts artifacts: '**/output/*.png', fingerprint: true
      //slackSend color: 'bad', message: "https://jenkins.planx-pla.net $env.JOB_NAME pipeline failed"
    }
    unstable {
      echo "Unstable!"
      //slackSend color: 'bad', message: "https://jenkins.planx-pla.net $env.JOB_NAME pipeline unstable"
    }
    always {
      script {
        // junit archiver does not like old looking files
        sh("touch gen3-qa/output/*.xml")
        uid = BUILD_TAG.replaceAll(' ', '_').replaceAll('%2F', '_')
        sh("bash cloud-automation/gen3/bin/klock.sh unlock jenkins "+uid)
      }
      echo "done"
      junit "gen3-qa/output/*.xml"
    }
  }
}