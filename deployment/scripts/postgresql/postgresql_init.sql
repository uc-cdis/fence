/*
Set up PostgreSQL for testing
See example usage in ADO pipeline: (under ../../../azure-devops-pipeline.yaml)
*/

CREATE DATABASE fence_test_tmp;
ALTER USER postgres WITH PASSWORD 'postgres';