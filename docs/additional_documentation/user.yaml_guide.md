# A guide to customizing authorization via user.yaml in Gen3

## Table of Contents

- [Introduction](#introduction)
- [Format](#format)
  - [Programs and projects CRUD access](#programs-and-projects-crud-access)
  - [Notes](#notes)
- [Deprecated format](#deprecated-format)
  - [For Gen3 Data Commons that do not use Arborist or use the Google Data Access method of Google Service Account Registration](#for-gen3-data-commons-that-do-not-use-arborist-or-use-the-google-data-access-method-of-google-service-account-registration)
- [Public data](#public-data)
  - [Public access to resources](#public-access-to-resources)
  - [The "/open" resource](#the-open-resource)

## Introduction

The `user.yaml` file is one way to get authorization information into Gen3. It is ingested via [Fence's `usersync` script](usersync.md). The format of this file is tightly coupled with the notions of resource, role and policy as defined by Gen3's policy engine, [Arborist](https://github.com/uc-cdis/arborist#arborist).

For Gen3 Data Commons that do not use Arborist or that use the Google Data Access method of [Google Service Account Registration](https://github.com/uc-cdis/fence/blob/master/docs/additional_documentation/google_architecture.md#google-account-linking-and-service-account-registration), refer to the [Deprecated format](#deprecated-format) section.

In a fully deployed Gen3 Commons using [Cloud Automation](https://github.com/uc-cdis/cloud-automation), the `user.yaml` file is usually hosted in S3 and configured via the `global.useryaml_s3path` setting of the Gen3 Data Commons manifest:
```
{
  "global": {
    "useryaml_s3path": "s3://bucket-name/path/to/user.yaml",
    ...
  },
  ...
}
```

A template, ready-to-use `user.yaml` file can be found [here](../base_user.yaml).

When updating your `user.yaml` file, you should use the [`gen3users` CLI](https://github.com/uc-cdis/gen3users#gen3users) to validate it before use.

## Format

Note that the `user.yaml` example below is minimal, as the goal is only to describe its structure. For a working `user.yaml` file that contains everything needed to get started, refer to the [base user.yaml](../base_user.yaml) instead.

```
authz:
  # policies automatically given to anyone, even if they are not authenticated
  anonymous_policies:
  - open_data_reader

  # policies automatically given to authenticated users (in addition to their other policies)
  all_users_policies: []

  # each group can contain multiple policies and multiple users
  groups:
  - name: program1_readers
    policies:
    - program1_reader
    users:
    - username1@domain.com

  # resource tree
  resources:
  - name: open
  - name: programs
    subresources:
    - name: program1

  # each policy can contain multiple roles and multiple resources
  policies:
  - id: open_data_reader
    role_ids:
    - reader
    - storage_reader
    resource_paths:
    - /open
  - id: program1_reader
    description: Read access to program1
    role_ids:
    - reader
    - storage_reader
    resource_paths:
    - /programs/program1
  - id: program1_indexd_admin
    description: Admin access to program1
    role_ids:
    - indexd_admin
    resource_paths:
    - /programs/program1

  # currently existing methods are `read`, `create`, `update`,
  # `delete`, `read-storage` and `write-storage`
  roles:
  - id: reader
    permissions:
    - id: reader
      action:
        method: read
        service: '*'
  - id: storage_reader
    permissions:
    - id: storage_reader
      action:
        method: read-storage
        service: '*'
  - id: creator
    permissions:
    - id: creator
      action:
        method: create
        service: '*'
  - id: indexd_admin
    permissions:
    - id: indexd_admin
      action:
        method: '*'
        service: indexd

# OIDC clients
clients:
  client1:
    policies:
    - open_data_reader

# all users must be defined here, even if they are not granted
# any individual permissions outside of the groups they are in.
# additional arbitrary information can be added in `tags`.
users:
  username1@domain.com: {}
  username2:
    tags:
      name: John Doe
      email: johndoe@domain.com
    policies:
    - program1_reader
```

The resource tree contains, among other resources, the programs and projects created via [Sheepdog](https://github.com/uc-cdis/sheepdog). If you created a program `{ "name": "program1" }` and a project `{ "name": "project1", "dbgap_accession_number": "phs1", "code": "P1" }`, your resource tree should contain the following:
```
  resources:
  - name: programs
    subresources:
    - name: program1
      subresources:
      - name: projects
        subresources:
        - name: P1
```
Policies would refer to this resource as `/programs/program1/projects/P1`.

There are several ways to attach a policy to a user:
- In the `users` section, under the appropriate username, in the list of `policies`;
- In the `groups` section, add the username to the group's `users` and the policy to the group's `policies`;
- In the `anonymous_policies` group, add policies that anyone should have (there is no need to set specific usernames in this case);
- In the `all_users_policies` group, add policies that all logged in users should have (there is no need to set specific usernames in this case).

Policies can also be attached to Fence OIDC clients in the `clients` section. Use the client's `name` (not `client_id`) to grant access to a client.

### Programs and projects CRUD access

```
{"message":"You don't have access to this resource: Unauthorized: User must be Sheepdog program admin"}
```

If you are using Arborist and you get this error message when trying to create a program or a project, you need to add the following to your `user.yaml` file and grant the `services.sheepdog-admin` policy to admin users:

- resources:
```
    - name: services
      subresources:
        - name: sheepdog
          subresources:
            - name: submission
              subresources:
                - name: program
                - name: project
```

- role:
```
    # Sheepdog admin role
    - id: sheepdog_admin
      description: sheepdog admin role for program project crud
      permissions:
        - id: sheepdog_admin_action
          action:
            service: sheepdog
            method: '*'
```

- policy:
```
    - id: services.sheepdog-admin
      description: CRUD access to programs and projects
      role_ids:
        - sheepdog_admin
      resource_paths:
        - /services/sheepdog/submission/program
        - /services/sheepdog/submission/project
```

### Notes

- While Arborist itself allows granular and inherited access through use of its resource tree / paths, granular access control beyond the `program` and `project` in the current Gen3 graph is not supported at the moment.
- Arborist does not support policies granting access to a root resource `/`.

## Deprecated format

The global `cloud_providers` and `groups` sections are deprecated.

The `users.admin` flag used below is the deprecated way of granting program and project CRUD access.

The `users.projects` section used below is the deprecated way of providing access. We should now use `users.policies` for individual access and `groups` for group access.

```
users:
  username1:
    admin: true
    projects:
    - auth_id: program1
      privilege:
      - read
      - read-storage
      - write-storage
```

### For Gen3 Data Commons that do not use Arborist or use the Google Data Access method of Google Service Account Registration

When Arborist is not being used (which is when the deprecated `acl` field of [Indexd](https://github.com/uc-cdis/indexd) records is used for access control instead of the newer `authz` field), or when the Google Data Access method of Google Service Account Registration is used, only the access granted to users through the deprecated `user.yaml` format will take effect. This is how you should configure your `user.yaml` if you are not using Arborist:

```
authz:
  user_project_to_resource:
    program1: /programs/program1

  resources:
  - name: programs
    subresources:
    - name: program1
    - name: program2

users:
  username1:
    projects:
    - auth_id: program1
      privilege:
      - read
    - auth_id: program2
      resource: /programs/program2
      privilege:
      - read
```

The `user_project_to_resource` section can be used to avoid specifying a resource path for each `users.projects.resource`.

## Public data

> What is involved in making a project "public"; that is, making both the metadata and object files accessible to anyone who visits the Data Commons?

### Public access to resources

Arborist can be configured to apply a policy to _all_ users who visit the system. This is done via the special `user.yaml` field `anonymous_policies`. Note that the same can be done with `all_users_policies` instead of `anonymous_policies` if access should be granted to all authenticated users instead of both authenticated and non-authenticated users.

The example below shows the setup for a program `PUBLIC_PROGRAM` and a project `PROJECT_1` under it. Because the policy `PUBLIC_PROGRAM_reader`, which grants access to this program, is in `anonymous_policies`, this program and all the subresources under it are accessible to all users.

Structured graph data in program `PUBLIC_PROGRAM` and data files whose indexd records' `authz` field includes `/programs/PUBLIC_PROGRAM/projects/PROJECT_1` will both be publicly accessible.

```
authz:
    # policies automatically given to anyone, even if they haven't authenticated
    anonymous_policies:
    - PUBLIC_PROGRAM_reader

    resources:
    - name: programs
      subresources:
      - name: PUBLIC_PROGRAM
        subresources:
        - name: projects
          subresources:
          - name: PROJECT_1

    policies:
    - id: PUBLIC_PROGRAM_reader
      role_ids:
      - reader
      - storage_reader
      resource_paths:
      - /programs/PUBLIC_PROGRAM
```

Arborist is very flexible: we could define an open policy per public program, or per public project, or even a single open policy with a list of all open resources.

### The "/open" resource

> Note that we may alter the behavior around "/open" in the future so as not to have hard-coded resource logic in Fence, so relying on this behavior is not recommended.

`/open` is a special resource supported by Gen3. It is only used for data files (in the `authz` field of indexd records).

An indexd record's `authz` field containing the resouce path `/open` means that Fence doesn't need to sign presigned URLs. Fence will assume the bucket is public. When a user tries to download the file, Fence will return a non-signed URL.

If the bucket is _not_ public but the data should be publicly accessible, public access should be granted via the `user.yaml` file but `/open` should _not_ be added in the `authz` field.

The example below shows how to set up public access to the `/open` resource.

```
authz:
    # policies automatically given to anyone, even if they haven't authenticated
    anonymous_policies:
    - open_data_reader

    resources:
    - name: open

    policies:
    - id: open_data_reader
      role_ids:
      - reader
      - storage_reader
      resource_paths:
      - /open
```
