docker-build:
	# Building the docker image "rebrow"
	docker build -t rebrow .

docker-testrun:
	# Running the docker image, linked to a redis container
	docker run --rm -ti -p 5001:5001 --link redis:redis -e "SECRET_KEY=abc123" rebrow
