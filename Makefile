.PHONY: run build test clean deps help

# Default target
help: ## Show this help
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

deps: ## Install dependencies
	go mod download
	go mod tidy

build: ## Build the application
	go build -o bin/oauth2-api main.go

run: ## Run the application
	go run main.go

test: ## Run tests
	go test ./...

test-api: ## Run API integration tests
	./test_api.sh

test-client: ## Run Go client test
	cd test && go run client.go

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f *.db

dev: deps ## Setup development environment
	@echo "Development environment ready!"
	@echo "Run 'make run' to start the server"

docker-build: ## Build Docker image
	docker build -t oauth2-api .

docker-run: ## Run Docker container
	docker run -p 8080:8080 oauth2-api

.DEFAULT_GOAL := help
