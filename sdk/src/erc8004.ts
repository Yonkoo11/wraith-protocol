/**
 * ERC-8004 (Trustless Agents) integration for Cipher Pol
 *
 * EIP-8004 gives AI agents a verifiable on-chain identity, reputation, and
 * a mechanism for independent task validation. Cipher Pol integrates ERC-8004 to:
 *   1. Identify agents making x402 payments (x402Support: true)
 *   2. Generate payment receipts after successful API calls
 *   3. Enable reputation building across the agent ecosystem
 *
 * Spec: https://eips.ethereum.org/EIPS/eip-8004
 * Status: Live on Ethereum mainnet as of January 29, 2026
 *
 * The agent registration file follows the EIP-8004 schema exactly.
 * Notably, `x402Support: true` is a first-class field in the spec —
 * Cipher Pol agents are the canonical implementation of this feature.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AgentManifest {
  type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
  name: string;
  description: string;
  image?: string;
  services: ServiceEntry[];
  /** Always true for CipherPol agents — x402 is our payment mechanism */
  x402Support: true;
  active: boolean;
  supportedTrust: Array<'reputation' | 'crypto-economic' | 'tee-attestation'>;
  registrations?: RegistrationEntry[];
  /** CipherPol-specific extension fields */
  cipherPol: {
    sdkVersion: string;
    adapter: 'privacy-pools' | 'strk20';
    starknetAddress?: string;
    privacyLevel: 'demo' | 'weak' | 'strong' | 'zk-native';
  };
}

export interface ServiceEntry {
  name: 'x402' | 'web' | 'A2A' | 'MCP' | 'OASF';
  endpoint: string;
  version?: string;
}

export interface RegistrationEntry {
  agentId: number;
  /** Structured as 'eip155:{chainId}:{identityRegistryAddress}' */
  agentRegistry: string;
}

/**
 * ERC-8004 payment receipt — the off-chain feedback file format.
 *
 * After a Cipher Pol x402 payment, the agent generates this receipt.
 * It can be submitted to the ERC-8004 Reputation Registry as feedback,
 * proving the agent autonomously paid for a service via ZK-private Starknet tx.
 */
export interface AgentReceipt {
  /** ERC-8004 agent ID (ERC-721 token on Identity Registry, if registered) */
  agentId?: string;
  /** Agent ETH address registered on ERC-8004 Identity Registry */
  agentEthAddress?: string;
  /** Agent Starknet address that made the actual payment */
  agentStarknetAddress?: string;
  /** URI to agent's ERC-8004 registration file (IPFS, HTTPS, or data:) */
  agentURI?: string;
  /** API endpoint that was accessed after payment */
  service: string;
  /**
   * ERC-8004 proofOfPayment structure (from spec off-chain feedback format).
   * Note: fromAddress is the Starknet address; chainId is starknet-* not EVM.
   * The ZK proof links deposit→withdrawal without revealing depositor identity.
   */
  paymentProof: {
    fromAddress: string;
    toAddress: string;
    chainId: string;
    txHash: string;
  };
  amount: string;
  token: string;
  timestamp: number;
  /** Schema identifier for tooling */
  schema: 'erc8004-cipher-pol-receipt-v1';
}

export interface ERC8004Config {
  /** Human-readable agent name */
  name: string;
  /** What this agent does */
  description: string;
  /** ETH address for ERC-8004 Identity Registry wallet (optional) */
  ethAddress?: string;
  /** Starknet address that performs x402 payments */
  starknetAddress?: string;
  /** ERC-8004 agent ID if already registered on Identity Registry */
  agentId?: number;
  /** Identity Registry: 'eip155:{chainId}:{address}' (e.g. 'eip155:1:0x...') */
  registryAddress?: string;
}

// ── Functions ─────────────────────────────────────────────────────────────────

/**
 * Create an ERC-8004 compliant agent manifest.
 *
 * The manifest can be hosted at HTTPS, stored on IPFS, or encoded as a
 * data: URI and passed to `register(agentURI)` on the Identity Registry.
 *
 * @example
 * const manifest = createAgentManifest(
 *   { name: 'WeatherAgent', description: 'Fetches weather data autonomously' },
 *   'privacy-pools',
 *   'demo'
 * );
 * const uri = manifestToDataURI(manifest);
 * // Register on Ethereum: identityRegistry.register(uri)
 */
export function createAgentManifest(
  config: ERC8004Config,
  adapter: 'privacy-pools' | 'strk20',
  privacyLevel: 'demo' | 'weak' | 'strong' | 'zk-native'
): AgentManifest {
  const manifest: AgentManifest = {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: config.name,
    description: config.description,
    services: [
      {
        name: 'x402',
        endpoint: config.starknetAddress ?? 'starknet',
        version: 'cipher-pol-v1',
      },
    ],
    x402Support: true,
    active: true,
    supportedTrust: ['crypto-economic'],
    cipherPol: {
      sdkVersion: '0.1.0',
      adapter,
      starknetAddress: config.starknetAddress,
      privacyLevel,
    },
  };

  if (config.agentId !== undefined && config.registryAddress) {
    manifest.registrations = [
      {
        agentId: config.agentId,
        agentRegistry: config.registryAddress,
      },
    ];
  }

  return manifest;
}

/**
 * Encode an agent manifest as a data: URI.
 *
 * Pass this to `identityRegistry.register(uri)` on Ethereum to register the agent.
 * The data: URI is self-contained and verifiable without hosting infrastructure.
 */
export function manifestToDataURI(manifest: AgentManifest): string {
  const json = JSON.stringify(manifest, null, 2);
  const b64 = Buffer.from(json).toString('base64');
  return `data:application/json;base64,${b64}`;
}

/**
 * Generate an ERC-8004 payment receipt after a successful Cipher Pol x402 payment.
 *
 * This receipt proves the agent autonomously paid for a service via a
 * ZK-private Starknet transaction. It follows the ERC-8004 off-chain
 * feedback file format and can be submitted to the Reputation Registry.
 *
 * @param txHash    Starknet deposit transaction hash
 * @param network   Starknet network identifier
 * @param poolAddress  Privacy pool contract address (payment intermediary)
 * @param service   URL of the API that was accessed
 * @param amount    Amount paid (in token base units)
 * @param token     Token identifier (USDC, STRK, etc.)
 * @param agent     Optional ERC-8004 agent config
 */
export function generatePaymentReceipt(
  txHash: string,
  network: string,
  poolAddress: string,
  service: string,
  amount: bigint,
  token: string,
  agent?: ERC8004Config
): AgentReceipt {
  const manifest = agent
    ? createAgentManifest(agent, 'privacy-pools', 'demo')
    : undefined;

  return {
    agentId: agent?.agentId?.toString(),
    agentEthAddress: agent?.ethAddress,
    agentStarknetAddress: agent?.starknetAddress,
    agentURI: manifest ? manifestToDataURI(manifest) : undefined,
    service,
    paymentProof: {
      fromAddress: agent?.starknetAddress ?? 'unknown',
      toAddress: poolAddress,
      chainId: network,
      txHash,
    },
    amount: amount.toString(),
    token,
    timestamp: Date.now(),
    schema: 'erc8004-cipher-pol-receipt-v1',
  };
}

/**
 * Verify an ERC-8004 receipt has all required fields.
 * Useful for API servers to validate inbound agent receipts.
 */
export function validateReceipt(receipt: unknown): receipt is AgentReceipt {
  if (typeof receipt !== 'object' || receipt === null) return false;
  const r = receipt as Record<string, unknown>;
  return (
    r.schema === 'erc8004-cipher-pol-receipt-v1' &&
    typeof r.service === 'string' &&
    typeof r.paymentProof === 'object' &&
    typeof (r.paymentProof as Record<string, unknown>).txHash === 'string' &&
    typeof r.timestamp === 'number'
  );
}
