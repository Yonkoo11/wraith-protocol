/**
 * WithdrawalQueue — submit pre-generated ZK proofs to the Ekubo Privacy Pool.
 *
 * The agent generates the Groth16 proof CLIENT-SIDE and sends only the proof
 * (as a felt252 array) to the server. The server's job here is simple:
 *   1. Receive a pre-generated proof (30-felt HTTP transport format)
 *   2. Reconstruct the raw snarkjs proof JSON from the 30-felt encoding
 *   3. Generate garaga 0.15.3 calldata (full_proof_with_hints) via Python subprocess
 *   4. Submit to pool.withdraw() on Starknet
 *   5. Retry on failure (up to 3 times)
 *
 * The server NEVER generates ZK proofs — it never sees (secret, nullifier).
 * The server NEVER calls Lit Protocol — that design flaw is gone.
 *
 * Privacy model:
 * - Server receives: zkProof (felt252 array) + nullifierHash (public signal)
 * - Server learns:   that someone paid at timestamp T, and the payment amount
 * - Server does NOT: learn which deposit this corresponds to, or the depositor address
 *
 * On-chain:
 * - pool.withdraw(garagaCalldata) verifies the Groth16 proof via the garaga verifier
 * - If proof is valid: recipient receives funds, nullifier is stored (prevents replay)
 * - If proof is invalid: tx reverts, no funds move (server loses nothing; it served
 *   the request in good faith, same as any HTTP API trusting a client-provided token)
 *
 * Withdrawal timing:
 * - Requests are served immediately after nullifier check (proof not yet on-chain)
 * - Withdrawals are batched to reduce gas overhead (default: 5-minute intervals)
 * - For high-value APIs: set flushIntervalMs=0 to submit immediately before serving
 *
 * garaga 0.15.3 note:
 * - Must use garaga 0.15.3 (matching the compiled verifier contract, NOT garaga 1.x)
 * - garaga 1.0.1 dropped include_digits_decomposition=True in MSM calldata
 * - Install: pip install garaga==0.15.3 (under python3.10 or compatible)
 * - Set garagaPath to the garaga installation dir (contains hydra/)
 */

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Account, RpcProvider } from 'starknet';
import { deserializeProofFromFelts } from 'cipher-pol-agent';

interface QueuedWithdrawal {
  zkProof: string[];
  nullifierHash: string;
  amount: bigint;
  queuedAt: number;
  attempts: number;
}

export interface WithdrawalQueueConfig {
  /** Starknet account that signs and submits pool.withdraw() transactions */
  account: Account;
  /** Deployed Ekubo Privacy Pool contract address */
  poolAddress: string;
  /** Starknet RPC URL */
  rpcUrl: string;
  /**
   * Absolute path to circuits/verification_key.json.
   * Garaga needs this to generate full_proof_with_hints calldata.
   */
  vkPath: string;
  /**
   * Absolute path to the garaga 0.15.3 installation directory (contains hydra/).
   * Typically: /path/to/project/vendor/garaga-v0.15.3  OR  /tmp/garaga-v0.15.3
   * Must be 0.15.3 — later versions changed the calldata format.
   */
  garagaPath: string;
  /** Python interpreter to use for garaga (default: 'python3.10') */
  pythonPath?: string;
  /** Flush interval in ms (default: 5 minutes, 0 = flush on every enqueue) */
  flushIntervalMs?: number;
  /** Max withdrawal attempts before dropping (default: 3) */
  maxAttempts?: number;
  /** Called when a withdrawal is confirmed on-chain */
  onConfirmed?: (txHash: string, nullifierHash: string) => void;
  /** Called when a withdrawal fails permanently after maxAttempts */
  onFailed?: (nullifierHash: string, error: Error) => void;
}

export class WithdrawalQueue {
  private queue: QueuedWithdrawal[] = [];
  private readonly config: Required<WithdrawalQueueConfig>;
  private timer?: ReturnType<typeof setInterval>;
  private readonly provider: RpcProvider;

  constructor(config: WithdrawalQueueConfig) {
    this.config = {
      pythonPath: 'python3.10',
      flushIntervalMs: 5 * 60 * 1000,
      maxAttempts: 3,
      onConfirmed: () => {},
      onFailed: () => {},
      ...config,
    };
    this.provider = new RpcProvider({ nodeUrl: config.rpcUrl });
  }

  start(): void {
    if (this.config.flushIntervalMs > 0) {
      this.timer = setInterval(() => void this.flush(), this.config.flushIntervalMs);
    }
    console.log(
      `[WithdrawalQueue] Started. Pool=${this.config.poolAddress}. ` +
      `Flush interval: ${this.config.flushIntervalMs / 1000}s`
    );
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * Enqueue a pre-generated ZK proof for withdrawal.
   *
   * The zkProof is the felt252 array from generatePaymentProof() on the agent side.
   * Format: [pi_a (4), pi_b (8), pi_c (4), public_signals (14)] = 30 felts as strings.
   *
   * If flushIntervalMs=0, submits immediately (synchronous relative to caller).
   */
  enqueue(zkProof: string[], nullifierHash: string, amount: bigint): void {
    this.queue.push({ zkProof, nullifierHash, amount, queuedAt: Date.now(), attempts: 0 });

    if (this.config.flushIntervalMs === 0) {
      void this.flush();
    }
  }

  get pendingCount(): number {
    return this.queue.length;
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    // Snapshot the current queue WITHOUT removing items.
    // Items stay in this.queue until either confirmed on-chain or permanently failed.
    // This means a crash mid-flush leaves unprocessed items for the next interval,
    // rather than silently dropping them (the old splice(0) behaviour).
    // NOTE: this still loses items on process exit — Redis backing is the production fix.
    const toProcess = this.queue.slice();
    console.log(`[WithdrawalQueue] Flushing ${toProcess.length} withdrawal(s)...`);

    for (const item of toProcess) {
      try {
        await this.submitWithdrawal(item);
        // Success: remove from the live queue
        const idx = this.queue.indexOf(item);
        if (idx !== -1) this.queue.splice(idx, 1);
      } catch (err) {
        item.attempts += 1;

        if (item.attempts >= this.config.maxAttempts) {
          // Permanently failed: remove and notify
          const idx = this.queue.indexOf(item);
          if (idx !== -1) this.queue.splice(idx, 1);
          const error = err instanceof Error ? err : new Error(String(err));
          console.error(
            `[WithdrawalQueue] DROPPED after ${this.config.maxAttempts} attempts`,
            error
          );
          this.config.onFailed(item.nullifierHash, error);
        } else {
          // Transient failure: item stays in queue for next flush interval
          console.error(
            `[WithdrawalQueue] Withdrawal failed (attempt ${item.attempts}/${this.config.maxAttempts}), will retry at next flush`,
            err
          );
        }
      }
    }
  }

  /**
   * Generate garaga 0.15.3 calldata from the 30-felt transport encoding.
   *
   * Steps:
   *   1. Reconstruct snarkjs proof JSON from 30-felt HTTP transport encoding
   *   2. Write proof.json + public_signals.json to temp dir
   *   3. Run garaga Python script to produce full_proof_with_hints calldata
   *   4. Return calldata as string[] (garaga format: [span_len, elem1, ..., elemN])
   *
   * This must use garaga 0.15.3 — the same version used to compile the verifier contract.
   */
  private generateGaragaCalldata(zkProof: string[]): string[] {
    const { proof, publicSignals } = deserializeProofFromFelts(zkProof);

    // Use a cryptographically random tag to avoid collision and leave no
    // predictable forensic artifact in /tmp.
    const tag = crypto.randomUUID();
    const tmpDir = os.tmpdir();
    const proofPath  = path.join(tmpDir, `cipher-pol-proof-${tag}.json`);
    const pubPath    = path.join(tmpDir, `cipher-pol-pub-${tag}.json`);
    const cdOutPath  = path.join(tmpDir, `cipher-pol-cd-${tag}.json`);

    fs.writeFileSync(proofPath, JSON.stringify(proof));
    fs.writeFileSync(pubPath,   JSON.stringify(publicSignals));

    // Write Python script to a temp file to avoid shell-escaping issues
    const pyPath = path.join(tmpDir, `cipher-pol-garaga-${tag}.py`);
    const pyScript = [
      'import sys, json',
      `sys.path.insert(0, '${this.config.garagaPath}/hydra')`,
      'from garaga.starknet.groth16_contract_generator.calldata import groth16_calldata_from_vk_and_proof',
      'from garaga.starknet.groth16_contract_generator.parsing_utils import Groth16Proof, Groth16VerifyingKey',
      `vk = Groth16VerifyingKey.from_json('${this.config.vkPath}')`,
      `proof = Groth16Proof.from_json(proof_path='${proofPath}', public_inputs_path='${pubPath}')`,
      'calldata = groth16_calldata_from_vk_and_proof(vk, proof)',
      `json.dump([str(x) for x in calldata], open('${cdOutPath}', 'w'))`,
      'print(len(calldata))',
    ].join('\n');
    fs.writeFileSync(pyPath, pyScript);

    // execFileSync (not execSync) — avoids shell expansion/injection.
    // pythonPath and pyPath are server-controlled, but execFile ensures no
    // shell metacharacters in either path can execute additional commands.
    // Blocking the event loop is a known limitation; garaga calldata generation
    // takes ~1-3s. For high-throughput servers, move this to a worker_threads
    // pool to avoid blocking the accept loop.
    try {
      execFileSync(this.config.pythonPath, [pyPath], {
        timeout: 60_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const stderr = (err as NodeJS.ErrnoException & { stderr?: Buffer }).stderr?.toString() ?? '';
      throw new Error(`garaga calldata generation failed: ${msg}\n${stderr}`);
    } finally {
      try { fs.unlinkSync(proofPath); } catch {}
      try { fs.unlinkSync(pubPath);   } catch {}
      try { fs.unlinkSync(pyPath);    } catch {}
    }

    const calldata = JSON.parse(fs.readFileSync(cdOutPath, 'utf8')) as string[];
    try { fs.unlinkSync(cdOutPath); } catch {}

    if (!calldata || calldata.length < 30) {
      throw new Error(
        `garaga returned ${calldata?.length ?? 0} felts — expected ~2918. ` +
        `Check that garagaPath points to garaga 0.15.3 (not 1.x).`
      );
    }

    return calldata;
  }

  private async submitWithdrawal(item: QueuedWithdrawal): Promise<void> {
    // Do NOT log nullifierHash — even a prefix can be used to correlate
    // HTTP request timestamps with on-chain withdrawal events.
    // Use queue index or item count for operational logging instead.
    console.log(`[WithdrawalQueue] Submitting withdrawal: amount=${item.amount}, attempt=${item.attempts + 1}`);

    // Reconstruct garaga 0.15.3 calldata from the 30-felt HTTP transport encoding.
    // The pool.withdraw() entry point expects full_proof_with_hints format, NOT
    // the raw 30-felt transport array. Using the raw array would revert every time.
    const calldata = this.generateGaragaCalldata(item.zkProof);

    console.log(
      `[WithdrawalQueue] garaga calldata: ${calldata.length} felts. Submitting...`
    );

    // fn withdraw(proof: Span<felt252>) -> bool
    // calldata[0] is the span length (Cairo Span encoding); rest are the felts.
    const { transaction_hash } = await this.config.account.execute({
      contractAddress: this.config.poolAddress,
      entrypoint: 'withdraw',
      calldata,
    });

    console.log(
      `[WithdrawalQueue] Withdrawal submitted: txHash=${transaction_hash}, ` +
      `nullifier=${item.nullifierHash.slice(0, 20)}...`
    );

    this.config.onConfirmed(transaction_hash, item.nullifierHash);
  }
}

