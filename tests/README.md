Set environment variable PROMETHEUS_MULTIPROC_DIR to an arbitrary directory on your machine.

Example: PROMETHEUS_MULTIPROC_DIR=/Users/someone/.gen3/fence

Create a postgresql database to run the fence tests

1. docker pull postgres
1. docker run --name fence_test_db -p 5432:5432 -it -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=fence_test_tmp -d postgres

At the time of writing, docker pull postgres grabbed version 16.2.
