def combine_provided_and_dbgap_resources(useryaml_resources, arborist_paths):
    """
    Combine provided user.yaml resources loaded into python list of dictionaries
    and a list of string that are arborist resource paths for dbgap.

    Args:
        useryaml_resources (list(dict)): Description
        arborist_paths (list(str)): Description

    Returns:
        list(dict): list of dictionaries representing arborist data to PUT to
                    resource endpoint
    """
    arborist_resources = _get_arborist_resources_from_paths(arborist_paths)
    dictified_useryaml_resources = _dictify_subresources(useryaml_resources)

    arborist_resources.append(dictified_useryaml_resources)

    rolled_together = _knead(arborist_resources)
    undictified = _undictify_subresources(rolled_together)

    return undictified


def _get_arborist_resources_from_paths(given_paths):
    """
    Take list of paths and return them in the form of a list of
    nested dictionaries where resource names are keys and subresources are values

    input: [
        "/programs/phs000172",
        "/orgA/programs/phs000175",
        "/orgC/programs/phs000175",
        "/programs/phs000178",
        "/orgA/programs/phs000179",
        "/orgB/programs/phs000179"
    ]

    output:
        [{'programs': {'phs000172': {}}},
         {'orgA': {'programs': {'phs000175': {}}}},
         {'orgC': {'programs': {'phs000175': {}}}},
         {'programs': {'phs000178': {}}},
         {'orgA': {'programs': {'phs000179': {}}}},
         {'orgB': {'programs': {'phs000179': {}}}}]
    """

    paths = []
    for path in [path for path in given_paths if path]:
        paths.append(path.strip("/").split("/"))

    resources = []
    for path in paths:
        resource = _get_resource(path)
        resources.append(resource)

    return resources


def _get_resource(path):
    root = {}
    d = root
    for x in path:
        d[x] = {}
        d = d[x]
    return root


def _knead(resources):
    root = {}
    for resource in resources:
        _insert_resource(resource, root)
    return root


def _insert_resource(resource, root):
    r = resource
    while len(r):
        item = r.popitem()
        if item[0] in root:
            _insert_resource(item[1], root[item[0]])
        else:
            root[item[0]] = item[1]


def _undictify_subresources(root):
    d = []
    while len(root):
        item = root.popitem()
        resource = {}
        resource["name"] = item[0]
        resource["subresources"] = _undictify_subresources(item[1])
        d.append(resource)
    return d


def _dictify_subresources(list_of_resources):
    root = {}
    for resource in list_of_resources:
        dictified_subresources = (
            _dictify_subresources(resource["subresources"])
            if "subresources" in resource
            else {}
        )
        if resource["name"] in root:
            _insert_resource(dictified_subresources, root["name"])
        else:
            root[resource["name"]] = dictified_subresources
    return root
