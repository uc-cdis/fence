#!groovy

pipeline {
  agent any

  environment {
    // hardcoded environment variable for namespace 
    KUBECTL_NAMESPACE = 'qa-bloodpac'
  }

  stages {
    stage('FetchCode') {
      steps {
        dir('gen3-qa') {
          git(
            url: 'https://github.com/uc-cdis/gen3-qa.git',
            branch: 'master'
          )
        }
        dir('cdis-manifest') {
          git(
            url: 'https://github.com/uc-cdis/cdis-manifest.git',
            branch: 'QA'
          )
        }
        dir('cloud-automation') {
          git(
            url: 'https://github.com/uc-cdis/cloud-automation.git',
            branch: 'master'
          )
        }
      }
    }
    stage('ModifyManifest') {
      steps {
        dir('cdis-manifest') {
          ls
          echo "$env.JOB_NAME"
          echo "$env.HOSTNAME"
          echo "$env.KUBECTL_NAMESPACE.planx-pla.net"
          // withEnv([""]) {
          //   ls
          //   dir("$env.KUBECTL_NAMESPACE.planx-pla.net") {
          //     ls

          //   }
          // }
        }
      }
    }
    // stage('CheckManifest') {
    //   steps {
    //     dir('cdis-manifest/') {
    //       ls
    //       dir() {

    //       }
    //     }
    //   }
    // }
    stage('K8sDeploy') {
      steps {
        withEnv(['GEN3_NOPROXY=true', "vpc_name=$env.KUBECTL_NAMESPACE", "GEN3_HOME=$env.WORKSPACE/cloud-automation"]) {
          echo "GEN3_HOME is $env.GEN3_HOME"
          echo "GIT_BRANCH is $env.GIT_BRANCH"
          echo "GIT_COMMIT is $env.GIT_COMMIT"
          echo "KUBECTL_NAMESPACE is $env.KUBECTL_NAMESPACE"
          echo "WORKSPACE is $env.WORKSPACE"
          // sh "bash cloud-automation/gen3/bin/kube-roll-all.sh"
          // sh "bash cloud-automation/gen3/bin/kube-wait4-pods.sh || true"
        }
      }
    }
    stage('RunInstall') {
      steps {
        dir('gen3-qa') {
          withEnv(['GEN3_NOPROXY=true']) {
            // sh "bash ./run-install.sh"
          }
        }
      }
    }
    stage('RunTests') {
      steps {
        dir('gen3-qa') {
          withEnv(['GEN3_NOPROXY=true', "vpc_name=$env.KUBECTL_NAMESPACE", "GEN3_HOME=$env.WORKSPACE/cloud-automation"]) {
            // sh "bash ./run-tests.sh $env.KUBECTL_NAMESPACE"
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
      // junit "gen3-qa/output/*.xml"
    }
  }
}