docker build -t fence .
docker tag fence:latest cginmn/fence
docker push cginmn/fence:latest

