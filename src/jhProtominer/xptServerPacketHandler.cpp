#include"global.h"

/*
 * Sends the response for an auth packet
 */
bool xptServer_sendAuthResponse(xptServer_t* xptServer, xptServerClient_t* xptServerClient, uint32 authErrorCode, char* rejectReason)
{
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptServer->sendBuffer, XPT_OPC_S_AUTH_ACK);
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, authErrorCode);
	// write reject reason string (or motd in case of no error)
	sint32 rejectReasonLength = strlen(rejectReason);
	xptPacketbuffer_writeU16(xptServer->sendBuffer, &sendError, (uint16)rejectReasonLength);
	xptPacketbuffer_writeData(xptServer->sendBuffer, (uint8*)rejectReason, (uint32)rejectReasonLength, &sendError);
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptServer->sendBuffer);
	// send to client
	send(xptServerClient->clientSocket, (const char*)(xptServer->sendBuffer->buffer), xptServer->sendBuffer->parserIndex, 0);
	return true;
}

/*
 * Generates the block data and sends it to the client
 */
bool xptServer_sendBlockData(xptServer_t* xptServer, xptServerClient_t* xptServerClient)
{
	// we need several callbacks to the main work manager:
	if( xptServerClient->payloadNum < 1 || xptServerClient->payloadNum > 128 )
	{
		printf("xptServer_sendBlockData(): payloadNum out of range for worker %s\n", xptServerClient->workerName);
		return false;
	}
	// generate work
	xptBlockWorkInfo_t blockWorkInfo;
	xptWorkData_t workData[128];
	if( xptServer->xptCallback_generateWork(xptServer, xptServerClient->payloadNum, xptServerClient->coinTypeIndex, &blockWorkInfo, workData) == false )
	{
		printf("xptServer_sendBlockData(): Unable to generate work data for worker %s\n", xptServerClient->workerName);
		return false;
	}
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptServer->sendBuffer, XPT_OPC_S_WORKDATA1);
	// add general block info
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, blockWorkInfo.height);				// block height
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, blockWorkInfo.nBits);				// nBits
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, blockWorkInfo.nBitsShare);			// nBitsRecommended / nBitsShare
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, blockWorkInfo.nTime);				// nTimestamp
	xptPacketbuffer_writeData(xptServer->sendBuffer, blockWorkInfo.prevBlockHash, 32, &sendError);	// prevBlockHash
	xptPacketbuffer_writeU32(xptServer->sendBuffer, &sendError, xptServerClient->payloadNum);		// payload num
	for(uint32 i=0; i<xptServerClient->payloadNum; i++)
	{
		// add merkle root for each work data entry
		xptPacketbuffer_writeData(xptServer->sendBuffer, workData[i].merkleRoot, 32, &sendError);
	}
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptServer->sendBuffer);
	// send to client
	send(xptServerClient->clientSocket, (const char*)(xptServer->sendBuffer->buffer), xptServer->sendBuffer->parserIndex, 0);
	return true;
}

/*
 * Called when an authentication request packet is received
 * This packet must arrive before any other packet
 */
bool xptServer_processPacket_authRequest(xptServer_t* xptServer, xptServerClient_t* xptServerClient)
{
	return true;
}