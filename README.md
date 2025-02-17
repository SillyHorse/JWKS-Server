1. **Initialize GO Module**
pip install go
go mod init jwks-server-go
go mod tidy

2. **Start Server**
go run main.go

3. **Test Endpoints**
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
