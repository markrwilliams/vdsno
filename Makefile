all: example vdsno
vdsno:
	go build vdsno.go
clean:
	rm -f example vdsno
