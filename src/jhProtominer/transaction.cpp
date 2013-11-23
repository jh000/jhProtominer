#include"global.h"

void bitclient_addVarIntFromStream(stream_t* msgStream, uint64 varInt)
{
	if( varInt <= 0xFC )
	{
		stream_writeU8(msgStream, (uint8)varInt);
		return;
	}
	else if( varInt <= 0xFFFF )
	{
		stream_writeU8(msgStream, 0xFD);
		stream_writeU16(msgStream, (uint16)varInt);
		return;
	}
	else if( varInt <= 0xFFFFFFFF )
	{
		stream_writeU8(msgStream, 0xFE);
		stream_writeU32(msgStream, (uint32)varInt);
		return;
	}
	else
	{
		stream_writeU8(msgStream, 0xFF);
		stream_writeData(msgStream, &varInt, 8);
		return;
	}
}

void bitclient_generateTxHash(uint32 userExtraNonceLength, uint8* userExtraNonce, uint32 coinBase1Length, uint8* coinBase1, uint32 coinBase2Length, uint8* coinBase2, uint8* txHash)
{
	stream_t* streamTXData = streamEx_fromDynamicMemoryRange(1024*32);
	stream_writeData(streamTXData, coinBase1, coinBase1Length);
	stream_writeData(streamTXData, userExtraNonce, userExtraNonceLength);
	stream_writeData(streamTXData, coinBase2, coinBase2Length);
	sint32 transactionDataLength = 0;
	uint8* transactionData = (uint8*)streamEx_map(streamTXData, &transactionDataLength);
	// special case, we can use the hash of the transaction
	uint8 hashOut[32];
	sha256_ctx sctx;
	sha256_init(&sctx);
	sha256_update(&sctx, transactionData, transactionDataLength);
	sha256_final(&sctx, hashOut);
	sha256_init(&sctx);
	sha256_update(&sctx, hashOut, 32);
	sha256_final(&sctx, txHash);
	free(transactionData);
	stream_destroy(streamTXData);
}

void bitclient_calculateMerkleRoot(uint8* txHashes, uint32 numberOfTxHashes, uint8* merkleRoot)
{
	if(numberOfTxHashes <= 0 )
	{
		printf("bitclient_calculateMerkleRoot: Block has zero transactions (not even coinbase)\n");
		RtlZeroMemory(merkleRoot, 32);
		return;
	}
	else if( numberOfTxHashes == 1 )
	{
		// generate transaction data
		memcpy(merkleRoot, txHashes+0, 32);
		return;
	}
	else
	{
		// build merkle root tree
		uint8* hashData = (uint8*)malloc(32*(numberOfTxHashes+1)*2+32*128); // space for tx hashes and tree + extra space just to be safe
		uint32 hashCount = 0; // number of hashes written to hashData
		uint32 hashReadIndex = 0; // index of currently processed hash
		uint32 layerSize[16] = {0}; // up to 16 layers (which means 2^16 hashes are possible)
		layerSize[0] = numberOfTxHashes;
		for(uint32 i=0; i<numberOfTxHashes; i++)
		{
			memcpy(hashData+(hashCount*32), txHashes+(i*32), 32);
			hashCount++;
		}
		if(numberOfTxHashes&1 && numberOfTxHashes > 1 )
		{
			// duplicate last hash
			memcpy(hashData+(hashCount*32), hashData+((hashCount-1)*32), 32);
			hashCount++;
			layerSize[0]++;
		}
		// process layers
		for(uint32 f=0; f<10; f++)
		{
			if( layerSize[f] == 0 )
			{
				printf("bitclient_calculateMerkleRoot: Error generating merkleRoot hash\n");
				free(hashData);
				return;
			}
			else if( layerSize[f] == 1 )
			{
				// result found
				memcpy(merkleRoot, hashData+(hashReadIndex*32), 32);
				hashReadIndex++;
				free(hashData);
				return;
			}
			for(uint32 i=0; i<layerSize[f]; i += 2)
			{
				uint8 hashOut[32];
				sha256_ctx sha256_ctx;
				sha256_init(&sha256_ctx);
				sha256_update(&sha256_ctx, hashData+(hashReadIndex*32), 32*2);
				hashReadIndex += 2;
				sha256_final(&sha256_ctx, hashOut);
				sha256_init(&sha256_ctx);
				sha256_update(&sha256_ctx, hashOut, 32);
				sha256_final(&sha256_ctx, hashData+(hashCount*32));
				hashCount++;
				layerSize[f+1]++;
			}
			// do we need to duplicate the last hash?
			if( layerSize[f+1]&1 && layerSize[f+1] > 1 )
			{
				// duplicate last hash
				memcpy(hashData+(hashCount*32), hashData+((hashCount-1)*32), 32);
				hashCount++;
			}
		}
		free(hashData);
	}
}