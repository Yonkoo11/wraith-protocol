/**
 * Lit Protocol integration — optional encrypted note storage for Wraith agents
 *
 * Use case (v1):
 * - Agent generates (secret, nullifier) locally and produces the ZK proof client-side
 * - The server NEVER sees (secret, nullifier) — that is not what Lit is used for here
 * - Lit is used ONLY for cross-device note recovery: agent encrypts the note bundle
 *   so it can store it off-device and decrypt it later from another session
 *
 * What Lit does NOT do in Wraith v1:
 * - Does NOT send (secret, nullifier) to the server for proof generation (that was
 *   the pre-v1 design and is a fundamental privacy flaw — removed)
 * - Does NOT gate proof generation on-chain
 * - Is NOT on the critical payment path
 *
 * Access condition:
 * - Encrypts note so only the holder of apiEthAddress can decrypt
 * - apiEthAddress is an Ethereum address (not Starknet) — Lit v7 does not support
 *   native Starknet access conditions as of 2026-03
 * - Server authenticates with a dedicated Ethereum key (SERVER_ETH_PRIVATE_KEY)
 *
 * SDK: @lit-protocol/lit-node-client@^7.4, @lit-protocol/encryption@^7.4,
 *      @lit-protocol/auth-helpers@^7.4, @lit-protocol/constants@^7.4
 */

export interface EncryptedNote {
  ciphertext: string;
  dataToEncryptHash: string;
  accessControlConditions: unknown[];
  chain: string;
}

export interface DecryptedNote {
  secret: bigint;
  nullifier: bigint;
}

/**
 * Encrypt (secret, nullifier) for the API server.
 *
 * @param secret          - The deposit secret
 * @param nullifier       - The deposit nullifier
 * @param apiEthAddress   - Ethereum address of the API server (who can decrypt).
 *                          Must be the address corresponding to the server's
 *                          SERVER_ETH_PRIVATE_KEY. Do NOT derive this from a
 *                          Starknet address — use ethers.Wallet(pk).address.
 * @param litNetwork      - Lit network ('datil' for production, 'datil-dev' for local)
 */
export async function encryptNoteForAPI(
  secret: bigint,
  nullifier: bigint,
  apiEthAddress: string,
  litNetwork: string = 'datil'
): Promise<EncryptedNote> {
  if (!apiEthAddress.match(/^0x[0-9a-fA-F]{40}$/)) {
    throw new Error(
      `apiEthAddress must be a 20-byte Ethereum address (0x + 40 hex chars). ` +
      `Got: ${apiEthAddress}. ` +
      `Use ethers.Wallet(SERVER_ETH_PRIVATE_KEY).address — do not derive from Starknet address.`
    );
  }

  const { LitNodeClient } = await import('@lit-protocol/lit-node-client');
  const { encryptString } = await import('@lit-protocol/encryption');

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const client = new LitNodeClient({ litNetwork: litNetwork as any, debug: false });
  await client.connect();

  // Access condition: only the holder of apiEthAddress can decrypt.
  // Lit verifies this via a SIWE signature from the decryptor.
  // Note: Lit does not yet support native Starknet access conditions (as of v7.4).
  // The API server authenticates with a dedicated Ethereum key (SERVER_ETH_PRIVATE_KEY).
  const accessControlConditions = [
    {
      contractAddress: '',
      standardContractType: '',
      chain: 'ethereum',
      method: '',
      parameters: [':userAddress'],
      returnValueTest: {
        comparator: '=',
        value: apiEthAddress.toLowerCase(),
      },
    },
  ];

  const message = JSON.stringify({
    secret: secret.toString(16),
    nullifier: nullifier.toString(16),
  });

  const { ciphertext, dataToEncryptHash } = await encryptString(
    { accessControlConditions, dataToEncrypt: message },
    client
  );

  await client.disconnect();

  return {
    ciphertext,
    dataToEncryptHash,
    accessControlConditions,
    chain: 'ethereum',
  };
}

/**
 * Get Lit session signatures for a server ETH key (SIWE flow).
 *
 * Call this before decryptNoteFromAgent() to authenticate with the Lit network.
 * The signer must be the ethers.Wallet whose address matches the access condition
 * used in encryptNoteForAPI().
 *
 * @param signer      - ethers.Wallet with the server's ETH private key
 * @param litNetwork  - 'datil' (production) or 'datil-dev' (local testing)
 * @param capacityDelegationAuthSig - optional capacity delegation for rate limits
 */
export async function getLitSessionSigs(
  signer: import('ethers').Wallet,
  litNetwork = 'datil',
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  capacityDelegationAuthSig?: any
): Promise<Record<string, unknown>> {
  const { LitNodeClient } = await import('@lit-protocol/lit-node-client');
  const {
    createSiweMessage,
    generateAuthSig,
    LitAccessControlConditionResource,
  } = await import('@lit-protocol/auth-helpers');
  const { LIT_ABILITY } = await import('@lit-protocol/constants');

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const client = new LitNodeClient({ litNetwork: litNetwork as any, debug: false });
  await client.connect();

  const latestBlockhash = await client.getLatestBlockhash();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const params: any = {
    chain: 'ethereum',
    expiration: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    resourceAbilityRequests: [
      {
        resource: new LitAccessControlConditionResource('*'),
        ability: LIT_ABILITY.AccessControlConditionDecryption,
      },
    ],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    authNeededCallback: async (cbParams: any) => {
      const toSign = await createSiweMessage({
        uri:           cbParams.uri ?? 'https://localhost',
        expiration:    cbParams.expiration,
        resources:     cbParams.resourceAbilityRequests,
        walletAddress: signer.address,
        nonce:         latestBlockhash,
        litNodeClient: client,
      });
      return generateAuthSig({ signer, toSign });
    },
  };

  if (capacityDelegationAuthSig) {
    params.capacityDelegationAuthSig = capacityDelegationAuthSig;
  }

  const sessionSigs = await client.getSessionSigs(params);
  await client.disconnect();
  return sessionSigs as Record<string, unknown>;
}

/**
 * Decrypt a (secret, nullifier) bundle.
 *
 * @param encrypted   - The encrypted bundle from the agent
 * @param sessionSigs - Lit session sigs from getLitSessionSigs()
 */
export async function decryptNoteFromAgent(
  encrypted: EncryptedNote,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sessionSigs: any
): Promise<DecryptedNote> {
  const { LitNodeClient } = await import('@lit-protocol/lit-node-client');
  const { decryptToString } = await import('@lit-protocol/encryption');

  const client = new LitNodeClient({ litNetwork: 'datil', debug: false });
  await client.connect();

  const decrypted = await decryptToString(
    {
      accessControlConditions: encrypted.accessControlConditions,
      ciphertext: encrypted.ciphertext,
      dataToEncryptHash: encrypted.dataToEncryptHash,
      chain: encrypted.chain,
      sessionSigs,
    },
    client
  );

  await client.disconnect();

  const parsed = JSON.parse(decrypted);
  return {
    secret: BigInt('0x' + parsed.secret),
    nullifier: BigInt('0x' + parsed.nullifier),
  };
}

