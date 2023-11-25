all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-cmloot
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-cmloot.exe .

clean:
	rm -f go-cmloot
	rm -f go-cmloot.exe
