
void bitclient_generateTxHash(uint32 userExtraNonceLength, uint8* userExtraNonce, uint32 coinBase1Length, uint8* coinBase1, uint32 coinBase2Length, uint8* coinBase2, uint8* txHash);
void bitclient_calculateMerkleRoot(uint8* txHashes, uint32 numberOfTxHashes, uint8* merkleRoot);
// misc
void bitclient_addVarIntFromStream(stream_t* msgStream, uint64 varInt);