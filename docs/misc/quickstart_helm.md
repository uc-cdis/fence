## Quickstart with Helm

If you are looking to deploy all Gen3 services, that can be done via the Gen3 Helm chart.
Instructions for deploying all Gen3 services with Helm can be found [here](https://github.com/uc-cdis/gen3-helm#readme).

To deploy the fence service:
```bash
helm repo add gen3 https://helm.gen3.org
helm repo update
helm upgrade --install gen3/fence
```
These commands will add the Gen3 helm chart repo and install the fence service to your Kubernetes cluster.

Deploying fence this way will use the defaults that are defined in this [values.yaml file](https://github.com/uc-cdis/gen3-helm/blob/master/helm/fence/values.yaml)

You can learn more about these values by accessing the fence [README.md](https://github.com/uc-cdis/gen3-helm/blob/master/helm/fence/README.md)

If you would like to override any of the default values, simply copy the above values.yaml file into a local file and make any changes needed.

To deploy the service independant of other services (for testing purposes), you can set the .postgres.separate value to "true". This will deploy the service with its own instance of Postgres:
```bash
  postgres:
    separate: true
```

You can then supply your new values file with the following command:
```bash
helm upgrade --install gen3/fence -f values.yaml
```

If you are using Docker Build to create new images for testing, you can deploy them via Helm by replacing the .image.repository value with the name of your local image.
You will also want to set the .image.pullPolicy to "never" so kubernetes will look locally for your image.
Here is an example:
```bash
image:
  repository: <image name from docker image ls>
  pullPolicy: Never
  # Overrides the image tag whose default is the chart appVersion.
  tag: ""
```

Re-run the following command to update your helm deployment to use the new image:
```bash
helm upgrade --install gen3/fence
```

You can also store your images in a local registry. Kind and Minikube are popular for their local registries:
- https://kind.sigs.k8s.io/docs/user/local-registry/
- https://minikube.sigs.k8s.io/docs/handbook/registry/#enabling-insecure-registries
