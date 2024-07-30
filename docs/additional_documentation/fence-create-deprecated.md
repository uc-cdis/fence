## Create components for testing

```bash
fence-create create path/to/file.yaml
```

The YAML file can contain project, users, groups and cloud providers. Example:
```
cloud_providers:
  google:
    backend: gs
    service: storage
projects:
  - name: project1
    auth_id: phs-project-unique-1
    storage_accesses:
      - name: google
        buckets: []
groups:
  group1:
    projects:
      - name: project1
        auth_id: phs-project-unique-1
        privilege:
          - read
          - read-storage
users:
  username:
    admin: false
    # does not work with userdatamodel 2.0.1
    # groups:
    #   - group1
    projects:
      - name: project1
        auth_id: phs-project-unique-1
        privilege:
          - read
    # clients:
    #   - {...}
```
This is a deprecated user.yaml format. But it can still be used to create components for testing.
