docker run --rm -it -v "%cd%/plugins:/app" -w /app golang:1.15.2 go build -buildmode=plugin -o headerModPlugin.so