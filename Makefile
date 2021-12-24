setup:
	docker-compose -f docker-compose.yml up --build -d
clean:
	docker-compose down
	docker image rm fail2ban
