//#define _WINSOCK_DEPRECATED_NO_WARNINGS
//
//#include <iostream>
//#include <string>
//#include <thread>
//#include <vector>
//#include <winsock2.h>
//#include <WS2tcpip.h>
//#pragma comment(lib, "ws2_32.lib")
//
//#define BUFFER_SIZE 4096
//
//using namespace std;
//
//typedef enum _IO_OPERATION {
//    ClientIoAccept,
//    ClientIoRead,
//    ClientIoWrite,
//    ServerIoRead,
//    ServerIoWrite
//} IO_OPERATION, * PIO_OPERATION;
//
//typedef struct {
//    WSAOVERLAPPED Overlapped;
//    SOCKET socket;
//    SOCKET peerSocket;
//    WSABUF wsaBufSend;
//    WSABUF wsaBufRecv;
//    char Buffer[BUFFER_SIZE];
//    DWORD BytesSent;
//    DWORD BytesRecv;
//    IO_OPERATION ioOperation;
//} PER_IO_DATA, * LPPER_IO_DATA;
//
//HANDLE ProxyCompletionPort;
//
//static DWORD WINAPI WorkerThread(LPVOID lparameter);
//LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation);
//SOCKET connect_to_target(const string& hostname, int port);
//string extract_host(const string& request);
//
//int main(void) {
//    WSADATA WsaData;
//    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
//        cerr << "WSAStartup failed" << endl;
//        return 1;
//    }
//    cout << "WSAStartup()" << endl;
//
//    ProxyCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
//    if (!ProxyCompletionPort) {
//        cerr << "CreateIoCompletionPort failed" << endl;
//        WSACleanup();
//        return 1;
//    }
//    cout << "CreateIoCompletionPort()" << endl;
//
//    SYSTEM_INFO systemInfo;
//    GetSystemInfo(&systemInfo);
//        for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++) {
//        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, ProxyCompletionPort, 0, NULL);
//        if (pThread == NULL) {
//            cerr << "Failed to create worker thread" << endl;
//            WSACleanup();
//            return 1;
//        }
//        CloseHandle(pThread);
//    }
//    cout << "WorkerThreads created" << endl;
//
//    SOCKET proxySocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
//    if (proxySocket == INVALID_SOCKET) {
//        cerr << "WSASocket failed" << endl;
//        WSACleanup();
//        return 1;
//    }
//    cout << "Proxy server socket created" << endl;
//
//    SOCKADDR_IN SockAddr;
//    ZeroMemory(&SockAddr, sizeof(SockAddr));
//    SockAddr.sin_family = AF_INET;
//    SockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
//    SockAddr.sin_port = htons(8080);
//
//    if (bind(proxySocket, (SOCKADDR*)&SockAddr, sizeof(SockAddr)) != 0) {
//        cerr << "Bind failed" << endl;
//        closesocket(proxySocket);
//        WSACleanup();
//        return 1;
//    }
//
//    if (listen(proxySocket, SOMAXCONN) != 0) {
//        cerr << "Listen failed" << endl;
//        closesocket(proxySocket);
//        WSACleanup();
//        return 1;
//    }
//
//    cout << "Waiting for connections on port 8080..." << endl;
//
//    while (TRUE) {
//        SOCKET clientSocket = INVALID_SOCKET;
//        do {
//            SOCKADDR_IN saClient;
//            int clientSize = sizeof(saClient);
//            clientSocket = WSAAccept(proxySocket, (SOCKADDR*)&saClient, &clientSize, NULL, NULL);
//        } while (clientSocket == INVALID_SOCKET);
//
//        cout << "Client accepted" << endl;
//
//        if (clientSocket != INVALID_SOCKET) {
//            LPPER_IO_DATA clientData = UpdateIoCompletionPort(clientSocket, INVALID_SOCKET, ClientIoRead);
//            if (!clientData) {
//                cerr << "Failed to update IO Completion Port" << endl;
//                closesocket(clientSocket);
//                continue;
//            }
//
//            DWORD flags = 0;
//            DWORD buffSize = 0;
//            if (WSARecv(clientData->socket, &clientData->wsaBufRecv, 1, &buffSize, &flags, &clientData->Overlapped, NULL) == SOCKET_ERROR) {
//                if (WSAGetLastError() != WSA_IO_PENDING) {
//                    cerr << "WSARecv failed" << endl;
//                    delete clientData;
//                    closesocket(clientSocket);
//                }
//            }
//            else {
//                cout << "From Client - Socket: " << clientData->socket << " Recv " << buffSize << " bytes." << endl;
//            }
//        }
//    }
//
//    WSACleanup();
//    return 0;
//}
//
//static DWORD WINAPI WorkerThread(LPVOID lparameter) {
//    HANDLE completionPort = (HANDLE)lparameter;
//    DWORD bytesTransferred = 0;
//    LPPER_IO_DATA sockData = NULL;
//    LPWSAOVERLAPPED overlapped = NULL;
//    DWORD dwNumBytes = 0;
//
//    while (TRUE) {
//        BOOL result = GetQueuedCompletionStatus(completionPort, &bytesTransferred, (PDWORD_PTR)&sockData, (LPOVERLAPPED*)&overlapped, INFINITE);
//        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;
//
//        if (!result || bytesTransferred == 0) {
//            cerr << "GetQueuedCompletionStatus failed or connection closed" << endl;
//            if (ioData) {
//                closesocket(ioData->socket);
//                if (ioData->peerSocket != INVALID_SOCKET) {
//                    closesocket(ioData->peerSocket);
//                }
//                delete ioData;
//            }
//            continue;
//        }
//
//        switch (ioData->ioOperation) {
//        case ClientIoRead: {
//            ioData->BytesRecv = bytesTransferred;
//            ioData->Buffer[bytesTransferred] = '\0';
//            ioData->ioOperation = ServerIoWrite;
//            string request(ioData->Buffer);
//            string hostname = extract_host(request);
//            cout << "Parsed request: " << hostname << endl;
//
//            if (!hostname.empty()) {
//                SOCKET serverSocket = connect_to_target(hostname, 80);
//                if (serverSocket != INVALID_SOCKET) {
//                    ioData->peerSocket = serverSocket;
//
//                    if (CreateIoCompletionPort((HANDLE)ioData->peerSocket, ProxyCompletionPort, NULL, 0) == NULL) {
//                        cerr << "CreateIoCompletionPort for server failed" << endl;
//                        closesocket(ioData->peerSocket);
//                        closesocket(ioData->socket);
//                        delete ioData;
//                        continue;
//                    }
//
//                    // Initiate WSASend to server
//                    if (WSASend(ioData->peerSocket, &ioData->wsaBufRecv, 1, NULL, 0, &ioData->Overlapped, NULL) == SOCKET_ERROR) {
//                        if (WSAGetLastError() != WSA_IO_PENDING) {
//                            cerr << "Failed to send request to server" << endl;
//                            closesocket(serverSocket);
//                            delete ioData;
//                        }
//                    }
//                    else {
//                        cout << "To Server - Socket: " << ioData->peerSocket << endl;
//                        
//                    }
//
//                }
//                else {
//                    cerr << "Failed to connect to server" << endl;
//                    closesocket(ioData->socket);
//                    delete ioData;
//                }
//            }
//            else {
//                cerr << "Invalid hostname" << endl;
//                closesocket(ioData->socket);
//                delete ioData;
//            }
//            break;
//        }
//
//        case ServerIoWrite: {
//            cout << "ServerIoWrite" << endl;
//            ioData->BytesSent = bytesTransferred;
//            ioData->ioOperation = ServerIoRead;
//            DWORD flags = 0;
//
//            if (WSARecv(ioData->peerSocket, &ioData->wsaBufSend, 1, &dwNumBytes, &flags, &ioData->Overlapped, NULL) == SOCKET_ERROR) {
//                int error = WSAGetLastError();
//                if (error != WSA_IO_PENDING) {
//                    cerr << "WSARecv failed with error: " << error << endl;
//                    closesocket(ioData->socket);
//                    closesocket(ioData->peerSocket);
//                    delete ioData;
//                }
//                else {
//                    cout << "WSARecv operation pending" << endl;
//                }
//            }
//            else {
//                cout << "From Server - Socket: " << ioData->peerSocket << endl;
//            }
//            break;
//        }
//
//        case ServerIoRead: {
//            cout << "ServerIoRead" << endl;
//            ioData->BytesRecv = bytesTransferred;
//            ioData->ioOperation = ClientIoWrite;
//            ioData->Buffer[bytesTransferred] = '\0';
//            DWORD flags = 0;
//
//            if (WSASend(ioData->socket, &ioData->wsaBufSend, 1, NULL, flags, &ioData->Overlapped, NULL) == SOCKET_ERROR) {
//                int error = WSAGetLastError();
//                if (error != WSA_IO_PENDING) {
//                    cerr << "WSASend failed with error: " << error << endl;
//                    closesocket(ioData->socket);
//                    closesocket(ioData->peerSocket);
//                    delete ioData;
//                }
//                else {
//                    cout << "WSASend operation pending" << endl;
//                }
//            }
//            else {
//                cout << "To Client - Socket: " << ioData->socket << endl;
//            }
//            break;
//        }
//
//        case ClientIoWrite: {
//            cout << "ClientIoWrite" << endl;
//            ioData->BytesSent = bytesTransferred;
//            ioData->ioOperation = ClientIoRead;
//            DWORD flags = 0;
//
//            if (WSARecv(ioData->socket, &ioData->wsaBufRecv, 1, &dwNumBytes, &flags, &ioData->Overlapped, NULL) == SOCKET_ERROR) {
//                int error = WSAGetLastError();
//                if (error != WSA_IO_PENDING) {
//                    cerr << "WSARecv failed with error: " << error << endl;
//                    closesocket(ioData->socket);
//                    closesocket(ioData->peerSocket);
//                    delete ioData;
//                }
//                else {
//                    cout << "WSARecv operation pending" << endl;
//                }
//            }
//            else {
//                cout << "From Client - Socket: " << ioData->socket << endl;
//            }
//            break;
//        }
//        }
//    }
//
//    return 0;
//}
//
//LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation) {
//    LPPER_IO_DATA socketData = new PER_IO_DATA();
//    ZeroMemory(socketData, sizeof(PER_IO_DATA));
//
//    socketData->socket = socket;
//    socketData->peerSocket = peerSocket;
//    socketData->ioOperation = ioOperation;
//    socketData->wsaBufRecv.buf = socketData->Buffer;
//    socketData->wsaBufRecv.len = BUFFER_SIZE;
//    socketData->wsaBufSend.buf = socketData->Buffer;
//    socketData->wsaBufSend.len = BUFFER_SIZE;
//
//    if (CreateIoCompletionPort((HANDLE)socket, ProxyCompletionPort, (DWORD)socketData, 0) == NULL) {
//        cerr << "CreateIoCompletionPort association failed" << endl;
//        delete socketData;
//        return NULL;
//    }
//
//    return socketData;
//}
//
//SOCKET connect_to_target(const string& hostname, int port) {
//    SOCKET sock;
//    struct addrinfo hints, * res, * p;
//    char port_str[6];
//    snprintf(port_str, sizeof(port_str), "%d", port);
//
//    memset(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//
//    if (getaddrinfo(hostname.c_str(), port_str, &hints, &res) != 0) {
//        cerr << "getaddrinfo failed" << endl;
//        return INVALID_SOCKET;
//    }
//
//    for (p = res; p != NULL; p = p->ai_next) {
//        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
//        if (sock == INVALID_SOCKET) {
//            continue;
//        }
//
//        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
//            closesocket(sock);
//            continue;
//        }
//        cout << "Connected to server" << endl;
//
//        break;
//    }
//
//    if (p == NULL) {
//        cerr << "Unable to connect to target server: " << hostname << endl;
//        freeaddrinfo(res);
//        return INVALID_SOCKET;
//    }
//
//    freeaddrinfo(res);
//    return sock;
//}
//
//string extract_host(const string& request) {
//    string host_header = "Host: ";
//    size_t start_pos = request.find(host_header);
//    if (start_pos == string::npos) {
//        return "";
//    }
//    start_pos += host_header.length();
//    size_t end_pos = request.find("\r\n", start_pos);
//    if (end_pos == string::npos) {
//        return "";
//    }
//    return request.substr(start_pos, end_pos - start_pos);
//}