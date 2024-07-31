
## Access Control / Authz

Currently fence works with another Gen3 service named
[arborist](https://github.com/uc-cdis/arborist) to implement attribute-based access
control for commons users. The YAML file of access control information (see
[#create-user-access-file](setup.md#create-user-access-file)) contains a section `authz` which are data sent to
arborist in order to set up the access control model.
