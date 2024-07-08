## Migration Tests

These tests are designed to test pre/post behavior of database migrations and making sure the changes are working as intended.

Currently we only have upgrade tests because the latest version of authlib has undergone major changes and will *not* work with previous versions of database schema.

For client class details, see fence/models.py
