docker run --rm -it -v "%cd%/plugin:/app" -w /app golang:1.15.2 go build -buildmode=plugin -o plugin.so .
REM docker run --rm -it -v "%cd%/server:/app" -w /app golang:1.15.2 go build -buildmode=plugin -o serverPlugin.so .
REM docker run --rm -it -v "%cd%/client:/app" -w /app golang:1.15.2 go build -buildmode=plugin -o clientPlugin.so .