from functools import reduce


def combine_provided_and_dbgap_resources(useryaml_resources, arborist_paths):
    """
    Combine provided user.yaml resources loaded into python list of dictionaries
    and a list of string that are arborist resource paths for dbgap.

    useryaml_resources should be read from user.yaml file into list of python dicts.
    The output should also be in that format, but should convert a list of
    arborist resources paths and combine that with resources from the user.yaml

    Example input:

        useryaml_resources: [
            {"name": "gen3", "subresources": [{"name": "programs"}]},
            {
                "name": "programs",
                "subresources": [
                    {
                        "name": "QA",
                        "subresources": [
                            {"name": "projects", "subresources": [{"name": "test"}]}
                        ],
                    },
                    {
                        "name": "DEV",
                        "subresources": [
                            {"name": "projects", "subresources": [{"name": "test"}]}
                        ],
                    },
                    {
                        "name": "phs000172",
                        "subresources": [
                            {"name": "projects", "subresources": [{"name": "test"}]}
                        ],
                    },
                ],
            },
        ]

        arborist_paths: [
            "/programs/phs000172",
            "/orgA/programs/phs000175",
            "/orgC/programs/phs000175",
            "/programs/phs000178",
            "/orgA/programs/phs000179",
            "/orgB/programs/phs000179",
        ]

        output: [
            {
                "name": "orgB",
                "subresources": [
                    {
                        "name": "programs",
                        "subresources": [{"name": "phs000179", "subresources": []}],
                    }
                ],
            },
            {
                "name": "orgC",
                "subresources": [
                    {
                        "name": "programs",
                        "subresources": [{"name": "phs000175", "subresources": []}],
                    }
                ],
            },
            {
                "name": "orgA",
                "subresources": [
                    {
                        "name": "programs",
                        "subresources": [
                            {"name": "phs000179", "subresources": []},
                            {"name": "phs000175", "subresources": []},
                        ],
                    }
                ],
            },
            {"name": "gen3", "subresources": [{"name": "programs", "subresources": []}]},
            {
                "name": "programs",
                "subresources": [
                    {
                        "name": "phs000172",
                        "subresources": [
                            {
                                "name": "projects",
                                "subresources": [{"name": "test", "subresources": []}],
                            }
                        ],
                    },
                    {
                        "name": "QA",
                        "subresources": [
                            {
                                "name": "projects",
                                "subresources": [{"name": "test", "subresources": []}],
                            }
                        ],
                    },
                    {"name": "phs000178", "subresources": []},
                    {
                        "name": "DEV",
                        "subresources": [
                            {
                                "name": "projects",
                                "subresources": [{"name": "test", "subresources": []}],
                            }
                        ],
                    },
                ],
            },
        ]

    Args:
        useryaml_resources (list(dict)): Description
        arborist_paths (list(str)): Description

    Returns:
        list(dict): list of dictionaries representing arborist data to PUT to
                    resource endpoint
    """

    def nest_resource(start, resource):
        root = start
        segments = resource.strip("/").split("/")

        def insert_segment(current, segment):
            if segment not in {c["name"] for c in current}:
                current.append({"name": segment, "subresources": []})
                i = -1
            else:
                # for future reference on what this is doing, an example:
                # In [1]: xs = [{"name": "a"}, {"name": "b"}, {"name": "c"}]

                # In [2]: list([c["name"] == "b" for c in xs])
                # Out[2]: [False, True, False]

                # In [3]: list([c["name"] == "b" for c in xs]).index(True)
                # Out[3]: 1
                i = list([c["name"] == segment for c in current]).index(True)

            if "subresources" not in current[i]:
                current[i]["subresources"] = []

            return current[i]["subresources"]

        reduce(insert_segment, segments, start)
        return root

    return reduce(nest_resource, arborist_paths, list(useryaml_resources))
