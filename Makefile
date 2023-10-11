all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o go-cmloot
	GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o go-cmloot.exe .

clean:
	rm -f go-cmloot
	rm -f go-cmloot.exe
