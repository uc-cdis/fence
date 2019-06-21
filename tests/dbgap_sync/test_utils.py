import yaml
from fence.sync import utils


def test_combine_arborist_resources():
    """
    Test that util function successfully combines arborist resources from a user.yaml
    file and list of arborist resource paths from dbgap into one format that can
    be used on the PUT resource endpoint of arborist.
    """
    yaml_string = """
    rbac:
      resources:
        - name: 'gen3'
          subresources:
            - name: 'programs'
        - name: 'programs'
          subresources:
            - name: 'QA'
              subresources:
                - name: 'projects'
                  subresources:
                    - name: 'test'
            - name: 'DEV'
              subresources:
                - name: 'projects'
                  subresources:
                    - name: 'test'
            - name: 'phs000172'
              subresources:
                - name: 'projects'
                  subresources:
                    - name: 'test'
    """
    useryaml = yaml.safe_load(yaml_string)
    useryaml_resources = useryaml.get("rbac", {}).get("resources")

    test_paths = [
        "/programs/phs000172",
        "/orgA/programs/phs000175",
        "/orgC/programs/phs000175",
        "/programs/phs000178",
        "/orgA/programs/phs000179",
        "/orgB/programs/phs000179",
    ]

    combined = utils.combine_provided_and_dbgap_resources(
        useryaml_resources, test_paths
    )

    expected_roots = ["orgA", "orgB", "orgC", "programs", "gen3"]
    for item in combined:
        # ensure one of each of the items in expected roots
        assert item.get("name") in expected_roots
        expected_roots.remove(item.get("name"))

        subresources = _get_subresources(item)

        # ensure result has correct subresources
        if item.get("name") == "OrgA":
            program_subresources = _get_subresources(subresources["programs"])
            assert "phs000179" in program_subresources
            assert "phs000175" in program_subresources
        elif item.get("name") == "OrgB":
            program_subresources = _get_subresources(subresources["programs"])
            assert "phs000179" in program_subresources
        elif item.get("name") == "OrgC":
            program_subresources = _get_subresources(subresources["programs"])
            assert "phs000175" in program_subresources
        elif item.get("name") == "programs":
            assert "phs000178" in subresources

            assert "phs000172" in subresources
            assert "projects" in _get_subresources(subresources["phs000172"])
            assert "test" in _get_subresources(
                _get_subresources(subresources["phs000172"])["projects"]
            )

            assert "QA" in subresources
            assert "projects" in _get_subresources(subresources["QA"])
            assert "test" in _get_subresources(
                _get_subresources(subresources["QA"])["projects"]
            )

            assert "DEV" in subresources
            assert "projects" in _get_subresources(subresources["DEV"])
            assert "test" in _get_subresources(
                _get_subresources(subresources["DEV"])["projects"]
            )

        elif item.get("name") == "gen3":
            assert "programs" in subresources


def _get_subresources(item):
    return {subr.get("name"): subr for subr in item.get("subresources")}
