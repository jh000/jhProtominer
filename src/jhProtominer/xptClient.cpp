#include"global.h"

/*
 * Tries to establish a connection to the given ip:port
 * Uses a blocking connect operation
 */
SOCKET xptClient_openConnection(char *IP, int Port)
{
	SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if( s == SOCKET_ERROR )
		return SOCKET_ERROR;
	SOCKADDR_IN addr;
	memset(&addr,0,sizeof(SOCKADDR_IN));
	addr.sin_family=AF_INET;
	addr.sin_port=htons(Port);
	addr.sin_addr.s_addr=inet_addr(IP);
	int result = connect(s,(SOCKADDR*)&addr,sizeof(SOCKADDR_IN));
	if( result )
	{
		return SOCKET_ERROR;
	}
	return s;
}

/*
 * Creates a new xptClient connection object, does not initiate connection right away
 */
xptClient_t* xptClient_create()
{
	// create xpt connection object
	xptClient_t* xptClient = (xptClient_t*)malloc(sizeof(xptClient_t));
	memset(xptClient, 0x00, sizeof(xptClient_t));
	// initialize object
	xptClient->disconnected = true;
	xptClient->clientSocket = SOCKET_ERROR;
	xptClient->sendBuffer = xptPacketbuffer_create(256*1024);
	xptClient->recvBuffer = xptPacketbuffer_create(256*1024);
	InitializeCriticalSection(&xptClient->cs_shareSubmit);
	InitializeCriticalSection(&xptClient->cs_workAccess);
	xptClient->list_shareSubmitQueue = simpleList_create(4);
	// return object
	return xptClient;
}

/*
 * Try to establish an active xpt connection
 * target is the server address and worker login data to use for connecting
 * Returns false on error or if already connected
 */
bool xptClient_connect(xptClient_t* xptClient, generalRequestTarget_t* target)
{
	// are we already connected?
	if( xptClient->disconnected == false )
		return false;
	// first try to connect to the given host/port
	SOCKET clientSocket = xptClient_openConnection(target->ip, target->port);
	if( clientSocket == SOCKET_ERROR )
		return false;
	// set socket as non-blocking
	unsigned int nonblocking=1;
	unsigned int cbRet;
	WSAIoctl(clientSocket, FIONBIO, &nonblocking, sizeof(nonblocking), NULL, 0, (LPDWORD)&cbRet, NULL, NULL);
	// initialize the connection details
	xptClient->clientSocket = clientSocket;
	strcpy_s(xptClient->username, 127, target->authUser);
	strcpy_s(xptClient->password, 127, target->authPass);
	// send worker login
	xptClient_sendWorkerLogin(xptClient);
	// mark as connected
	xptClient->disconnected = false;
	// return success
	return true;
}

/*
 * Forces xptClient into disconnected state
 */
void xptClient_forceDisconnect(xptClient_t* xptClient)
{
	if( xptClient->disconnected )
		return; // already disconnected
	if( xptClient->clientSocket != SOCKET_ERROR )
	{
		closesocket(xptClient->clientSocket);
		xptClient->clientSocket = SOCKET_ERROR;
	}
	xptClient->disconnected = true;
	// mark work as unavailable
	xptClient->hasWorkData = false;
}

/*
 * Disconnects and frees the xptClient instance
 */
void xptClient_free(xptClient_t* xptClient)
{
	xptPacketbuffer_free(xptClient->sendBuffer);
	xptPacketbuffer_free(xptClient->recvBuffer);
	if( xptClient->clientSocket != SOCKET_ERROR )
	{
		closesocket(xptClient->clientSocket);
	}
	simpleList_free(xptClient->list_shareSubmitQueue);
	free(xptClient);
}

const sint8 base58Decode[] =
{
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

/*
 * Utility function to decode base58 wallet address
 * dataOut should have at least 1/2 the size of base58Input
 * inputLength must not exceed 200
 */
bool xptClient_decodeBase58(char* base58Input, sint32 inputLength, uint8* dataOut, sint32* dataOutLength)
{
	if( inputLength == 0 )
		return false;
	if( inputLength > 200 )
		return false;
	sint32 writeIndex = 0;
	uint32 baseArray[32];
	uint32 baseTrack[32];
	memset(baseArray, 0x00, sizeof(baseArray));
	memset(baseTrack, 0x00, sizeof(baseTrack));
	uint32 baseArraySize = 1;
	baseArray[0] = 0;
	baseTrack[0] = 57;
	// calculate exact size of output
	for(sint32 i=0; i<inputLength-1; i++)
	{
		// multiply baseTrack with 58
		for(sint32 b=baseArraySize-1; b>=0; b--)
		{
			uint64 multiplyWithCarry = (uint64)baseTrack[b] * 58ULL;
			baseTrack[b] = (uint32)(multiplyWithCarry&0xFFFFFFFFUL);
			multiplyWithCarry >>= 32;
			if( multiplyWithCarry != 0 )
			{
				// add carry
				for(sint32 carryIndex=b+1; carryIndex<baseArraySize; carryIndex++)
				{
					multiplyWithCarry += (uint64)baseTrack[carryIndex];
					baseTrack[carryIndex] = (uint32)(multiplyWithCarry&0xFFFFFFFFUL);
					multiplyWithCarry >>= 32;
					if( multiplyWithCarry == 0 )
						break;
				}
				if( multiplyWithCarry )
				{
					// extend
					baseTrack[baseArraySize] = (uint32)multiplyWithCarry;
					baseArraySize++;
				}
			}
		}
	}
	// get length of output data
	sint32 outputLength = 0;
	uint64 last = baseTrack[baseArraySize-1];
	if( last&0xFF000000 )
		outputLength = baseArraySize*4;
	else if( last&0xFF0000 )
		outputLength = baseArraySize*4-1;
	else if( last&0xFF00 )
		outputLength = baseArraySize*4-2;
	else
		outputLength = baseArraySize*4-3;
	// convert base
	for(sint32 i=0; i<inputLength; i++)
	{
		if( base58Input[i] >= sizeof(base58Decode)/sizeof(base58Decode[0]) )
			return false;
		sint8 digit = base58Decode[base58Input[i]];
		if( digit == -1 )
			return false;
		// multiply baseArray with 58
		for(sint32 b=baseArraySize-1; b>=0; b--)
		{
			uint64 multiplyWithCarry = (uint64)baseArray[b] * 58ULL;
			baseArray[b] = (uint32)(multiplyWithCarry&0xFFFFFFFFUL);
			multiplyWithCarry >>= 32;
			if( multiplyWithCarry != 0 )
			{
				// add carry
				for(sint32 carryIndex=b+1; carryIndex<baseArraySize; carryIndex++)
				{
					multiplyWithCarry += (uint64)baseArray[carryIndex];
					baseArray[carryIndex] = (uint32)(multiplyWithCarry&0xFFFFFFFFUL);
					multiplyWithCarry >>= 32;
					if( multiplyWithCarry == 0 )
						break;
				}
				if( multiplyWithCarry )
				{
					// extend
					baseArray[baseArraySize] = (uint32)multiplyWithCarry;
					baseArraySize++;
				}
			}
		}
		// add base58 digit to baseArray with carry
		uint64 addWithCarry = (uint64)digit;
		for(sint32 b=0; addWithCarry != 0 && b<baseArraySize; b++)
		{
			addWithCarry += (uint64)baseArray[b];
			baseArray[b] = (uint32)(addWithCarry&0xFFFFFFFFUL);
			addWithCarry >>= 32;
		}
		if( addWithCarry )
		{
			// extend
			baseArray[baseArraySize] = (uint32)addWithCarry;
			baseArraySize++;
		}
	}
	*dataOutLength = outputLength;
	// write bytes to about
	for(sint32 i=0; i<outputLength; i++)
	{
		dataOut[outputLength-i-1] = (uint8)(baseArray[i>>2]>>8*(i&3));
	}
	return true;
}

/*
 * Converts a wallet address (any coin) to the coin-independent format that xpt requires and
 * adds it to the list of developer fees.
 *
 * integerFee is a fixed size integer representation of the fee percentage. Where 65535 equals 131.07% (1 = 0.002%)
 * Newer versions of xpt try to stay integer-only to support devices that have no FPU.
 * 
 * You may want to consider re-implementing this mechanism in a different way if you plan to
 * have at least some basic level of protection from reverse engineers that try to remove your fee (if closed source)
 */
void xptClient_addDeveloperFeeEntry(xptClient_t* xptClient, char* walletAddress, uint16 integerFee)
{
	uint8 walletAddressRaw[256];
	sint32 walletAddressRawLength = sizeof(walletAddressRaw);
	if( xptClient_decodeBase58(walletAddress, strlen(walletAddress), walletAddressRaw, &walletAddressRawLength) == false )
	{
		printf("xptClient_addDeveloperFeeEntry(): Failed to decode wallet address\n");
		return;
	}
	// is length valid?
	if( walletAddressRawLength != 25 )
	{
		printf("xptClient_addDeveloperFeeEntry(): Invalid length of decoded address\n");
		return;
	}
	// validate checksum
	uint8 addressHash[32];
	sha256_ctx s256c;
	sha256_init(&s256c);
	sha256_update(&s256c, walletAddressRaw, walletAddressRawLength-4);
	sha256_final(&s256c, addressHash);
	sha256_init(&s256c);
	sha256_update(&s256c, addressHash, 32);
	sha256_final(&s256c, addressHash);
	if( *(uint32*)(walletAddressRaw+21) != *(uint32*)addressHash )
	{
		printf("xptClient_addDeveloperFeeEntry(): Invalid checksum\n");
		return;
	}
	// address ok, check if there is still free space in the list
	if( xptClient->developerFeeCount >= XPT_DEVELOPER_FEE_MAX_ENTRIES )
	{
		printf("xptClient_addDeveloperFeeEntry(): Maximum number of developer fee entries exceeded\n");
		return;
	}
	// add entry
	memcpy(xptClient->developerFeeEntry[xptClient->developerFeeCount].pubKeyHash, walletAddressRaw+1, 20);
	xptClient->developerFeeEntry[xptClient->developerFeeCount].devFee = integerFee;
	xptClient->developerFeeCount++;
}


/*
 * Bitcoin's .setCompact() method without Bignum dependency
 * Does not support negative values
 */
void xptClient_getDifficultyTargetFromCompact(uint32 nCompact, uint32* hashTarget)
{
    unsigned int nSize = nCompact >> 24;
    bool fNegative     = (nCompact & 0x00800000) != 0;
    unsigned int nWord = nCompact & 0x007fffff;
    memset(hashTarget, 0x00, 32); // 32 byte -> 8 uint32
    if (nSize <= 3)
    {
        nWord >>= 8*(3-nSize);
        hashTarget[0] = nWord;
    }
    else
    {
        hashTarget[0] = nWord;
        for(uint32 f=0; f<(nSize-3); f++)
        {
            // shift by one byte
            hashTarget[7] = (hashTarget[7]<<8)|(hashTarget[6]>>24);
            hashTarget[6] = (hashTarget[6]<<8)|(hashTarget[5]>>24);
            hashTarget[5] = (hashTarget[5]<<8)|(hashTarget[4]>>24);
            hashTarget[4] = (hashTarget[4]<<8)|(hashTarget[3]>>24);
            hashTarget[3] = (hashTarget[3]<<8)|(hashTarget[2]>>24);
            hashTarget[2] = (hashTarget[2]<<8)|(hashTarget[1]>>24);
            hashTarget[1] = (hashTarget[1]<<8)|(hashTarget[0]>>24);
            hashTarget[0] = (hashTarget[0]<<8);
        }
    }
    if( fNegative )
    {
        // if negative bit set, set zero hash
        for(uint32 i=0; i<8; i++)
                hashTarget[i] = 0;
    }
}

/*
 * Sends the worker login packet
 */
void xptClient_sendWorkerLogin(xptClient_t* xptClient)
{
	uint32 usernameLength = min(127, (uint32)strlen(xptClient->username));
	uint32 passwordLength = min(127, (uint32)strlen(xptClient->password));
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_AUTH_REQ);
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 6);								// version
	xptPacketbuffer_writeString(xptClient->sendBuffer, xptClient->username, 128, &sendError);	// username
	xptPacketbuffer_writeString(xptClient->sendBuffer, xptClient->password, 128, &sendError);	// password
	//xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 1);							// payloadNum (removed in version 6)
	// write worker version to server
	xptPacketbuffer_writeString(xptClient->sendBuffer, minerVersionString, 45, &sendError);		// minerVersionString
	// developer fee (xpt version 6 and above)
	xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptClient->developerFeeCount);
	for(sint32 i=0; i<xptClient->developerFeeCount; i++)
	{
		xptPacketbuffer_writeU16(xptClient->sendBuffer, &sendError, xptClient->developerFeeEntry[i].devFee);
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptClient->developerFeeEntry[i].pubKeyHash, 20, &sendError);
	}
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
}

/*
 * Sends the share packet
 */
void xptClient_sendShare(xptClient_t* xptClient, xptShareToSubmit_t* xptShareToSubmit)
{
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_SUBMIT_SHARE);
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->merkleRoot, 32, &sendError);		// merkleRoot
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->prevBlockHash, 32, &sendError);	// prevBlock
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->version);				// version
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nTime);				// nTime
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nonce);				// nNonce
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nBits);				// nBits
	// algorithm specific
	if( xptShareToSubmit->algorithm == ALGORITHM_PRIME )
	{
		xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->sieveSize);			// sieveSize
		xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->sieveCandidate);		// sieveCandidate
		// bnFixedMultiplier
		xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->fixedMultiplierSize);
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->fixedMultiplier, xptShareToSubmit->fixedMultiplierSize, &sendError);
		// bnChainMultiplier
		xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->chainMultiplierSize);
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->chainMultiplier, xptShareToSubmit->chainMultiplierSize, &sendError);
	}
	else if( xptShareToSubmit->algorithm == ALGORITHM_SHA256 || xptShareToSubmit->algorithm == ALGORITHM_SCRYPT )
	{
		// original merkleroot (used to identify work)
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->merkleRootOriginal, 32, &sendError);
		// user extra nonce (up to 16 bytes)
		xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->userExtraNonceLength);
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->userExtraNonceData, xptShareToSubmit->userExtraNonceLength, &sendError);
	}
	else if( xptShareToSubmit->algorithm == ALGORITHM_PROTOSHARES )
	{
		// nBirthdayA
		xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nBirthdayA);
		// nBirthdayB
		xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nBirthdayB);
		// original merkleroot (used to identify work)
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->merkleRootOriginal, 32, &sendError);
		// user extra nonce (up to 16 bytes)
		xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->userExtraNonceLength);
		xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->userExtraNonceData, xptShareToSubmit->userExtraNonceLength, &sendError);
	}
	// share id (server sends this back in shareAck, so we can identify share response)
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 0);
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
}

/*
 * Sends a ping request, the server will respond with the same data as fast as possible
 * To measure latency we send a high precision timestamp
 */
void xptClient_sendPing(xptClient_t* xptClient)
{
	// Windows only for now
	LARGE_INTEGER hpc;
	QueryPerformanceCounter(&hpc);
	uint64 timestamp = (uint64)hpc.QuadPart;
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_PING);
	// timestamp
	xptPacketbuffer_writeU64(xptClient->sendBuffer, &sendError, timestamp);
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
}

/*
 * Processes a fully received packet
 */
bool xptClient_processPacket(xptClient_t* xptClient)
{
	// printf("Received packet with opcode %d and size %d\n", xptClient->opcode, xptClient->recvSize+4);
	if( xptClient->opcode == XPT_OPC_S_AUTH_ACK )
		return xptClient_processPacket_authResponse(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_WORKDATA1 )
		return xptClient_processPacket_blockData1(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_SHARE_ACK )
		return xptClient_processPacket_shareAck(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_MESSAGE )
		return xptClient_processPacket_message(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_PING )
		return xptClient_processPacket_ping(xptClient);
	// unknown opcodes are accepted too, for later backward compatibility
	return true;
}

/*
 * Checks for new received packets and connection events (e.g. closed connection)
 */
bool xptClient_process(xptClient_t* xptClient)
{
	if( xptClient == NULL )
		return false;
	// are there shares to submit?
	EnterCriticalSection(&xptClient->cs_shareSubmit);
	if( xptClient->list_shareSubmitQueue->objectCount > 0 )
	{
		for(uint32 i=0; i<xptClient->list_shareSubmitQueue->objectCount; i++)
		{
			xptShareToSubmit_t* xptShareToSubmit = (xptShareToSubmit_t*)xptClient->list_shareSubmitQueue->objects[i];
			xptClient_sendShare(xptClient, xptShareToSubmit);
			free(xptShareToSubmit);
		}
		// clear list
		xptClient->list_shareSubmitQueue->objectCount = 0;
	}
	LeaveCriticalSection(&xptClient->cs_shareSubmit);
	// check if we need to send ping
	uint32 currentTime = (uint32)time(NULL);
	if( xptClient->time_sendPing != 0 && currentTime >= xptClient->time_sendPing )
	{
		xptClient_sendPing(xptClient);
		xptClient->time_sendPing = currentTime + 240; // ping every 4 minutes
	}
	// check for packets
	sint32 packetFullSize = 4; // the packet always has at least the size of the header
	if( xptClient->recvSize > 0 )
		packetFullSize += xptClient->recvSize;
	sint32 bytesToReceive = (sint32)(packetFullSize - xptClient->recvIndex);
	// packet buffer is always large enough at this point
	sint32 r = recv(xptClient->clientSocket, (char*)(xptClient->recvBuffer->buffer+xptClient->recvIndex), bytesToReceive, 0);
	if( r <= 0 )
	{
		// receive error, is it a real error or just because of non blocking sockets?
		if( WSAGetLastError() != WSAEWOULDBLOCK )
		{
			xptClient->disconnected = true;
			return false;
		}
		return true;
	}
	xptClient->recvIndex += r;
	// header just received?
	if( xptClient->recvIndex == packetFullSize && packetFullSize == 4 )
	{
		// process header
		uint32 headerVal = *(uint32*)xptClient->recvBuffer->buffer;
		uint32 opcode = (headerVal&0xFF);
		uint32 packetDataSize = (headerVal>>8)&0xFFFFFF;
		// validate header size
		if( packetDataSize >= (1024*1024*2-4) )
		{
			// packets larger than 4mb are not allowed
			printf("xptServer_receiveData(): Packet exceeds 2mb size limit\n");
			return false;
		}
		xptClient->recvSize = packetDataSize;
		xptClient->opcode = opcode;
		// enlarge packetBuffer if too small
		if( (xptClient->recvSize+4) > xptClient->recvBuffer->bufferLimit )
		{
			xptPacketbuffer_changeSizeLimit(xptClient->recvBuffer, (xptClient->recvSize+4));
		}
	}
	// have we received the full packet?
	if( xptClient->recvIndex >= (xptClient->recvSize+4) )
	{
		// process packet
		xptClient->recvBuffer->bufferSize = (xptClient->recvSize+4);
		if( xptClient_processPacket(xptClient) == false )
		{
			xptClient->recvIndex = 0;
			xptClient->recvSize = 0;
			xptClient->opcode = 0;
			// disconnect
			if( xptClient->clientSocket != 0 )
			{
				closesocket(xptClient->clientSocket);
				xptClient->clientSocket = 0;
			}
			xptClient->disconnected = true;
			return false;
		}
		xptClient->recvIndex = 0;
		xptClient->recvSize = 0;
		xptClient->opcode = 0;
	}
	// return
	return true;
}

/*
 * Returns true if the xptClient connection was disconnected from the server or should disconnect because login was invalid or awkward data received
 * Parameter reason is currently unused.
 */
bool xptClient_isDisconnected(xptClient_t* xptClient, char** reason)
{
	return xptClient->disconnected;
}

/*
 * Returns true if the worker login was successful
 */
bool xptClient_isAuthenticated(xptClient_t* xptClient)
{
	return (xptClient->clientState == XPT_CLIENT_STATE_LOGGED_IN);
}

void xptClient_foundShare(xptClient_t* xptClient, xptShareToSubmit_t* xptShareToSubmit)
{
	EnterCriticalSection(&xptClient->cs_shareSubmit);
	simpleList_add(xptClient->list_shareSubmitQueue, xptShareToSubmit);
	LeaveCriticalSection(&xptClient->cs_shareSubmit);
}