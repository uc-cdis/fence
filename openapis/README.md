# OpenAPI/Swagger

This uses the [swagger-codegen](https://github.com/swagger-api) project to generate documentation.

To generate a `swagger.json` file from `swagger.yaml`:
```
swagger-codegen generate -i swagger.yaml -l swagger
```

Additionally, you can use the [online swagger editor](https://editor.swagger.io/) to preview result from
`swagger.yaml`.

See the swagger documentation for information on how to generate "pretty" documentation pages from the swagger JSON and YAML files.