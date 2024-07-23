"""
At the time of writing, Prometheus metrics out of the box can't be reset between each
unit test. To be able to write independent unit tests, we have to manually save the "previous
state" (see `prometheus_metrics_before` fixture) and compare it to the new state. This involves
manually parsing the "previous state" (a python object) and the "current state" (raw text) into
the same format so they can be compared:
{ "name": "", "labels": {}, "value": 0 }

The utility functions below can be used to check that the expected metrics have been recorded,
while discarding any previous metrics.

https://stackoverflow.com/questions/73198616/how-do-i-reset-a-prometheus-python-client-python-runtime-between-pytest-test-fun
"""


def _diff_new_metrics_from_old_metrics(new_metrics, old_metrics):
    """
    Return a dictionary of "current metrics" by comparing the "new metrics" (current state) to the "old metrics" (previous state).

    Metric format example: {
        'gen3_fence_login_total{client_id="test_azp",fence_idp="shib",idp="test_idp",shib_idp="university",user_sub="123"}': 2.0,
        'gen3_fence_login_total{client_id="test_azp",fence_idp="None",idp="all",shib_idp="None",user_sub="123"}': 3.0,

    Example:
        old_metrics = { 'metric1': 2, 'metric2': 2 }
        new_metrics = { 'metric1': 1, 'metric3': 1 }
        Returned value = {
            'metric1': 1 (difference between 2 and 1),
            'metric3': 1
        } (metric2 omitted since it is not part of the current state)

    Args:
        new_metrics (dict): format { <unparsed metric name and labels>: <metric value> }
        old_metrics (dict): format { <unparsed metric name and labels>: <metric value> }
    }
    """
    diff = {}
    for metric_name in old_metrics:
        if metric_name not in new_metrics:
            continue
        val = new_metrics[metric_name] - old_metrics[metric_name]
        if val != 0:
            diff[metric_name] = val
    for metric_name in new_metrics:
        if metric_name not in old_metrics:
            diff[metric_name] = new_metrics[metric_name]
    return diff


def _parse_raw_name_to_labels(text_metric):
    """
    Parse a raw metric name into a name and a dict of labels.

    Example:
        text_metric = `metric_name{param1="None",param2="upload",param3="['/test/path']"`
        Returned value = {
            "name": "metric_name",
            "labels": { "param1": "None", "param2": "upload", "param3": "['/test/path']" }
        }

    Args:
        text_metric (str)
    """
    name = text_metric.split("{")[0]
    labels = text_metric.split("{")[1].split("}")[0].split('",')
    labels = {l.split("=")[0]: l.split("=")[1].strip('"') for l in labels}
    return {"name": name, "labels": labels}


def assert_prometheus_metrics(metrics_before, text_metrics, expected_metrics):
    """
    Compare the previous state and the current state of prometheus metrics, and checks if the difference between the 2 is the same as the new metrics a test expects to have recorded.

    Expected: only provide labels we need to check for, the rest will be ignored

    Args:
        metrics_before (list<prometheus Metric objects>): previous state of prometheus metrics
            Example: [ Metric{ samples: [ Sample{ name: "", labels: {}, value: 0 } ] } ]
        text_metrics (str): current state
            Example
                # TYPE gen3_fence_login_total counter
                gen3_fence_login_total{client_id="test_azp",fence_idp="shib",idp="test_idp",shib_idp="university",user_sub="123"} 2.0
                # HELP gen3_fence_presigned_url_total Fence presigned urls
                # TYPE gen3_fence_presigned_url_total counter
                gen3_fence_presigned_url_total{acl="None",action="upload",authz="['/test/path']",bucket="s3://test-bucket",client_id="test_azp",drs="True",protocol="s3",user_sub="123"} 1.0
        expected_metrics (list<prometheus Metric objects>): the expected difference between previous state and current state.
            Only provide the labels we need to check; omitted labels will be ignored even if they
            are present in the current state.
            Example: [
                {
                    'name': 'gen3_fence_login_total',
                    'labels': {
                        'user_sub': '123', 'idp': 'all', 'fence_idp': 'None', 'shib_idp': 'None', 'client_id': 'test_azp'
                    },
                    'value': 3.0
                }
            ]
    """
    old_metrics = {}
    for m in metrics_before:
        for sample in m.samples:
            labels_text = ", ".join([f'{k}="{v}"' for k, v in sample.labels.items()])
            old_metrics[f"{sample.name}{{{labels_text}}}"] = sample.value
    print("Old metrics:")
    for k, v in old_metrics.items():
        print(f"- {k} = {v}")

    new_metrics = text_metrics.strip().split("\n")
    new_metrics = {
        " ".join(m.split(" ")[:-1]): float(m.split(" ")[-1])
        for m in new_metrics
        if not m.startswith("#")
    }
    print("Received metrics:")
    for k, v in new_metrics.items():
        print(f"- {k} = {v}")

    diff_metrics = _diff_new_metrics_from_old_metrics(new_metrics, old_metrics)
    current_metrics = []
    print("Diff:")
    for m, val in diff_metrics.items():
        parsed_m = _parse_raw_name_to_labels(m)
        parsed_m["value"] = val
        current_metrics.append(parsed_m)
        print(f"- {parsed_m}")

    print("Expecting metrics:")
    # check that for each metric+label combination, the value is identical to the expected value
    for expected_m in expected_metrics:
        found = False
        print(f"- {expected_m}")
        for current_m in current_metrics:  # look for the right metric
            if current_m["name"] != expected_m["name"]:
                continue
            # if the metric name is identical, check the labels
            right_labels = True
            for label_k, label_v in expected_m["labels"].items():
                if current_m["labels"].get(label_k) != str(label_v):
                    right_labels = False
                    break
            # if both the name and the labels are identical, this is the right metric:
            # check that the value is the same as expected
            if right_labels:
                assert (
                    current_m["value"] == expected_m["value"]
                ), f"Missing metric: {expected_m}"
                found = True
                break  # we found the right metric and it has the right value: moving on
        assert found, f"Missing metric: {expected_m}"
