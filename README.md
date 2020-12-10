# CS165 Final Project

### Group members:
* Donavon Cai
* Naid Ibarra

## Files
* The proxy application assumes the blacklist is in \<Project Directory\>/src/inputFiles/blacklistedObjects.txt
* Also in the inputFiles folder, there is a clientObjects.txt which can be used as input for the client.

## Instructions to run

### Make
* From the top of the project directory, run ./scripts/setup.sh
* Also run make in the certificates folder to generate the necessary key and crt files needed to run TLS.
* If there is a compile error related to pthread make sure that the CMakeLists.txt at the top contains this line:
 `set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")`
### Usage
* Executables must be run from \<Project Directory\>/build/src.
* server: `./server <port to listen on>`
* proxy: `./proxy <proxy port> <server port>`
 	* One use of this command creates 5 proxies. They will be listening on 5 consecutive ports beginning from \<proxy port\>.
	* For example, `./proxy 8000 9999` will create 5 proxies listening on ports 8000, 8001, 8002, 8003, 8004 that all connect to a server listening on port 9999.
* client: `./client <proxy port> <file with object requests>`
	* The client assumes that \<proxy port\> is the port of the first proxy.
	* `./client 8000 ../../src/inputFiles/clientObjects.txt` will connect a single client to 5 proxies listening on 8000, 8001, 8002, 8003, 8004, and request the objects listed in clientObjects.txt.

## Output
* For simplicity, the server returns "content of \<objectName\>" to any request it receives.
* Each proxy will print its proxy number, and the requested object from client, whether the object was received from the server or cache, and the contents of the object (or that the object is forbidden if it is in the blacklist).
* The client will print the name of the object, which proxy it will request from, and the reply.

## Implementation
* The server does not look for real files to respond to a request, and instead returns "content of \<objectName\>" to any request it receives.
* The proxy uses fork() to create 5 processes to simulate 5 proxies running at the same time, and use pthread() to handle multiple clients, in order to implement the cache.
	* This ensures 5 proxies will their own cache, which is shared between client threads, so that an object cached from one client's request can be given to another client.
