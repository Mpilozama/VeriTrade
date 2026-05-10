/**
 * VeriTrade AI — Frontend Application
 * Blockchain-Backed Trade Compliance Platform
 *
 * Architecture:
 *   1. ManifestForm   → Submit shipping data to FastAPI backend
 *   2. AIEngine       → Display risk verdict + reasoning log
 *   3. CryptoLayer    → Generate & display SHA-256 audit hash
 *   4. BlockchainLayer→ Anchor hash via MetaMask / ethers.js
 *   5. VerifyLayer    → Regulators confirm on-chain integrity
 *   6. TamperSim      → Demonstrate blockchain immutability
 */

'use strict';

// ─── CONFIG ─────────────────────────────────────────────────────────────────

const CONFIG = {
  API_BASE: 'http://127.0.0.1:8000',
  // Deployed contract address on Sepolia — update after `npx hardhat deploy`
  CONTRACT_ADDRESS: '0x551abC80669E61090FCd652C48ac45114d6a3690',
  // Minimal ABI — only the functions the frontend needs
  CONTRACT_ABI: [
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "auditHash",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "attemptedBy",
				"type": "address"
			}
		],
		"name": "DuplicateAnchorAttempt",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "auditHash",
				"type": "bytes32"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "anchoredBy",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "supplierName",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "verdict",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "HashAnchored",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_hexHash",
				"type": "bytes32"
			},
			{
				"internalType": "string",
				"name": "_supplierName",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_verdict",
				"type": "string"
			}
		],
		"name": "anchorHash",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "auditRecords",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exists",
				"type": "bool"
			},
			{
				"internalType": "address",
				"name": "anchoredBy",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "blockNumber",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "supplierName",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "verdict",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_hexHash",
				"type": "bytes32"
			}
		],
		"name": "isAnchored",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "totalAnchored",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_hexHash",
				"type": "bytes32"
			}
		],
		"name": "verifyHash",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exists",
				"type": "bool"
			},
			{
				"internalType": "address",
				"name": "anchoredBy",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "blockNumber",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "verdict",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
],
};

// ─── APP STATE ───────────────────────────────────────────────────────────────

const State = {
  auditRecord: null,       // The AI-generated audit JSON
  auditHash: null,         // Original SHA-256 hex string
  provider: null,          // ethers.js provider
  signer: null,            // Connected wallet signer
  contract: null,          // ethers Contract instance
  walletAddress: null,     // Connected wallet address
  anchorTxHash: null,      // Blockchain tx hash after anchoring
};

// ─── UTILITY ─────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);
const show = (id) => { const el = $(id); if (el) el.classList.remove('hidden'); };
const hide = (id) => { const el = $(id); if (el) el.classList.add('hidden'); };
const setText = (id, text) => { const el = $(id); if (el) el.textContent = text; };
const setHTML = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };

/** Format timestamp to locale string */
const formatDate = (isoStr) => new Date(isoStr).toLocaleString();

/** Truncate a hash for display */
const shortHash = (h, len = 16) => h ? `${h.slice(0, len)}...${h.slice(-8)}` : '—';

/** Animate a counter from 0 to target */
function animateCounter(el, target, duration = 1200) {
  const start = performance.now();
  const update = (now) => {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(ease * target);
    if (t < 1) requestAnimationFrame(update);
    else el.textContent = target;
  };
  requestAnimationFrame(update);
}

// ─── SECTION NAVIGATION ──────────────────────────────────────────────────────

const SECTIONS = ['landing', 'submit', 'verdict', 'anchor', 'verify'];

function showSection(name) {
  SECTIONS.forEach(s => {
    const el = $(`section-${s}`);
    if (el) el.classList.toggle('hidden', s !== name);
  });
  // Scroll to top of section
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─── LANDING ANIMATIONS ──────────────────────────────────────────────────────

function initLanding() {
  // Animate trade-route dots on the SVG globe
  const dots = document.querySelectorAll('.trade-route-dot');
  dots.forEach((dot, i) => {
    dot.style.animationDelay = `${i * 0.4}s`;
  });

  // Stats counters
  const counters = [
    { id: 'stat-shipments', val: 2847 },
    { id: 'stat-hashes',    val: 2847 },
    { id: 'stat-blocked',   val: 134  },
  ];
  counters.forEach(c => {
    const el = $(c.id);
    if (el) setTimeout(() => animateCounter(el, c.val), 600);
  });
}

// ─── WALLET CONNECTION ────────────────────────────────────────────────────────

async function connectWallet() {
  if (typeof window.ethereum === 'undefined') {
    showToast('MetaMask not detected. Please install MetaMask to anchor hashes.', 'error');
    return false;
  }
  try {
    // Request account access
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    State.provider = new ethers.BrowserProvider(window.ethereum);
    State.signer   = await State.provider.getSigner();
    State.walletAddress = await State.signer.getAddress();

    // Instantiate the contract
    State.contract = new ethers.Contract(
      CONFIG.CONTRACT_ADDRESS,
      CONFIG.CONTRACT_ABI,
      State.signer
    );

    // Update UI
    setText('wallet-address', shortHash(State.walletAddress, 10));
    show('wallet-connected-badge');
    hide('wallet-connect-btn');

    showToast(`Wallet connected: ${shortHash(State.walletAddress)}`, 'success');
    return true;
  } catch (err) {
    console.error('Wallet connection failed:', err);
    showToast('Wallet connection rejected.', 'error');
    return false;
  }
}

// ─── MANIFEST SUBMISSION ─────────────────────────────────────────────────────

async function submitManifest(e) {
  e.preventDefault();

  // Collect form values
  const cargoRaw = $('cargo-items').value;
  const esgRaw   = $('esg-certs').value;

  const payload = {
    supplier_id:          $('supplier-id').value.trim(),
    supplier_name:        $('supplier-name').value.trim(),
    origin_country:       $('origin-country').value.trim(),
    destination_country:  $('dest-country').value.trim(),
    cargo_items:          cargoRaw.split(',').map(s => s.trim()).filter(Boolean),
    esg_certifications:   esgRaw.split(',').map(s => s.trim()).filter(Boolean),
    declared_value_usd:   parseFloat($('declared-value').value),
    weight_kg:            parseFloat($('weight-kg').value),
    vessel_id:            $('vessel-id').value.trim() || null,
  };

  // Basic validation
  if (!payload.supplier_name || !payload.origin_country || !payload.destination_country) {
    showToast('Please fill in all required fields.', 'error');
    return;
  }

  // Show loading state
  const btn = $('submit-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Analysing Manifest…`;

  try {
    const res = await fetch(`${CONFIG.API_BASE}/api/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) throw new Error(`API error: ${res.status}`);

    const data = await res.json();
    State.auditRecord = data.audit_record;
    State.auditHash   = data.audit_hash;

    renderVerdict(data);
    showSection('verdict');

  } catch (err) {
    console.error('Assessment failed:', err);
    showToast(`Assessment failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Run AI Assessment`;
  }
}

// ─── VERDICT RENDERING ────────────────────────────────────────────────────────

function renderVerdict(data) {
  const record = data.audit_record;
  const verdict = record.verdict;

  // Risk score ring
  const score = record.risk_score;
  const ring = $('risk-ring');
  const scoreEl = $('risk-score-number');
  if (ring) {
    const circumference = 2 * Math.PI * 54;
    const offset = circumference * (1 - score / 100);
    ring.style.strokeDasharray = circumference;
    ring.style.strokeDashoffset = circumference;
    ring.style.stroke = score >= 60 ? '#ef4444' : score >= 30 ? '#f59e0b' : '#10b981';
    setTimeout(() => {
      ring.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)';
      ring.style.strokeDashoffset = offset;
    }, 100);
  }
  if (scoreEl) setTimeout(() => animateCounter(scoreEl, score), 200);

  // Verdict badge
  const badgeEl = $('verdict-badge');
  if (badgeEl) {
    badgeEl.textContent = verdict;
    badgeEl.className = `verdict-badge verdict-${verdict.toLowerCase()}`;
  }

  // Supplier info
  setText('v-supplier', record.supplier_name);
  setText('v-origin', record.origin_country);
  setText('v-destination', record.destination_country);
  setText('v-cargo', record.cargo_items.join(', '));
  setText('v-esg', record.esg_certifications.length ? record.esg_certifications.join(', ') : 'None declared');
  setText('v-timestamp', formatDate(record.timestamp_utc));
  setText('v-verdict-detail', record.verdict_detail);

  // Flags
  const flagsEl = $('v-flags');
  if (flagsEl) {
    flagsEl.innerHTML = record.flags.length
      ? record.flags.map(f => `<span class="flag-chip">${f.replace(/_/g, ' ')}</span>`).join('')
      : '<span class="flag-chip flag-clear">NO FLAGS</span>';
  }

  // Reasoning log
  const logEl = $('reasoning-log');
  if (logEl) {
    logEl.innerHTML = record.reasoning_log
      .map(line => {
        const cls = line.startsWith('⚠') ? 'log-warn' : line.startsWith('✓') ? 'log-ok' : 'log-info';
        return `<div class="log-line ${cls}">${line}</div>`;
      })
      .join('');
  }

  // AI INSIGHT - This shows the Noah AI reasoning
  const insightText = data.ai_insight || 'AI analysis unavailable for this shipment.';
  const proseEl = $('ai-insight-prose');
  if (proseEl) {
    proseEl.textContent = '';
    proseEl.classList.add('ai-typing');
    let i = 0;
    function typeChar() {
      if (i < insightText.length) {
        proseEl.textContent += insightText[i++];
        setTimeout(typeChar, 20);
      } else {
        proseEl.classList.remove('ai-typing');
      }
    }
    typeChar();
    show('ai-insight-card');
  }

  // Hash display
  setText('audit-hash-display', data.audit_hash);
  setText('audit-id-display', record.audit_id);

  // Store for tamper simulation
  if ($('tamper-original-hash')) {
    $('tamper-original-hash').textContent = data.audit_hash;
  }
}

// ─── BLOCKCHAIN ANCHOR ────────────────────────────────────────────────────────

async function anchorOnChain() {
  if (!State.auditRecord || !State.auditHash) {
    showToast('No audit record found. Please assess a manifest first.', 'error');
    return;
  }

  // Ensure wallet is connected
  if (!State.signer) {
    const connected = await connectWallet();
    if (!connected) return;
  }

  const btn = $('anchor-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Anchoring to Blockchain…`;

  try {
    /**
     * Convert the hex SHA-256 string to bytes32 for Solidity.
     * ethers.js: `ethers.id()` is keccak256 of a string — NOT what we want.
     * We need to treat our hex hash as raw bytes32.
     * Correct approach: prepend "0x" and pass as bytes32 hex literal.
     */
    const hashBytes32 = '0x' + State.auditHash;

    // Call the smart contract
    const tx = await State.contract.anchorHash(
      hashBytes32,
      State.auditRecord.supplier_name,
      State.auditRecord.verdict
    );

    showToast('Transaction submitted. Waiting for confirmation…', 'info');

    // Wait for 1 confirmation
    const receipt = await tx.wait(1);
    State.anchorTxHash = receipt.hash;

    // Update UI
    setText('tx-hash-display',    receipt.hash);
    setText('block-number-display', receipt.blockNumber);
    setText('tx-status',          'CONFIRMED');
    show('blockchain-confirmed');
    setText('sepolia-link-text',  shortHash(receipt.hash, 20));
    $('sepolia-explorer-link').href = `https://sepolia.etherscan.io/tx/${receipt.hash}`;

    showToast('Hash anchored on Ethereum Sepolia! 🎉', 'success');

  } catch (err) {
    console.error('Blockchain anchor error:', err);
    // Contract already has this hash — simulate as "already verified"
    if (err.message.includes('already anchored')) {
      showToast('Hash already on-chain — record is immutable.', 'info');
    } else {
      showToast(`Blockchain error: ${err.message.slice(0, 80)}`, 'error');
    }
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Anchor Digital Passport`;
  }
}

// ─── TAMPER SIMULATION ────────────────────────────────────────────────────────

async function simulateTamper() {
  if (!State.auditRecord || !State.auditHash) {
    showToast('No audit record to tamper. Submit a manifest first.', 'error');
    return;
  }

  const btn = $('tamper-btn');
  btn.disabled = true;

  // Step 1: Show the original clean record
  setText('tamper-original-hash', State.auditHash);
  setText('tamper-status', 'Injecting fraudulent data…');
  show('tamper-panel');

  await sleep(1200);

  // Step 2: Corrupt the audit record in memory
  const corruptedRecord = JSON.parse(JSON.stringify(State.auditRecord));
  corruptedRecord.verdict    = 'CLEARED';          // Flip the verdict
  corruptedRecord.risk_score = 12;                 // Fake a low score
  corruptedRecord.flags      = [];                 // Erase all flags
  corruptedRecord.reasoning_log.unshift(
    '✓ [FRAUDULENT] All compliance checks passed. Manually overridden.'
  );

  setText('tamper-modified-verdict', 'CLEARED (fraudulently)');
  setText('tamper-status', 'Recalculating hash of corrupted record…');

  await sleep(1000);

  // Step 3: Re-hash the corrupted record via the backend
  try {
    const res = await fetch(`${CONFIG.API_BASE}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        original_hash: State.auditHash,
        audit_record:  corruptedRecord,
      }),
    });
    const verification = await res.json();

    setText('tamper-new-hash', verification.recomputed_hash);

    await sleep(800);

    // Step 4: MISMATCH detected — trigger breach alert
    if (verification.tamper_detected) {
      $('tamper-status').textContent = '';
      show('breach-alert');
      document.body.classList.add('breach-mode');
      setTimeout(() => document.body.classList.remove('breach-mode'), 4000);
      showToast('CRITICAL: BLOCKCHAIN INTEGRITY VIOLATION DETECTED', 'error');
    }

  } catch (err) {
    showToast(`Verification error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
  }
}

function resetTamperSim() {
  hide('tamper-panel');
  hide('breach-alert');
  setText('tamper-status', '');
  setText('tamper-modified-verdict', '');
  setText('tamper-new-hash', '');
}

// ─── VERIFICATION PANEL ───────────────────────────────────────────────────────

async function verifyHash() {
  const hashInput = $('verify-hash-input').value.trim();
  if (!hashInput || hashInput.length !== 64) {
    showToast('Please enter a valid 64-character SHA-256 hash.', 'error');
    return;
  }

  const btn = $('verify-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Querying Blockchain…`;

  try {
    if (!State.provider) {
      State.provider = new ethers.BrowserProvider(window.ethereum);
    }
    const contract = new ethers.Contract(
      CONFIG.CONTRACT_ADDRESS,
      CONFIG.CONTRACT_ABI,
      State.provider
    );

    const result = await contract.verifyHash('0x' + hashInput);
    const [exists, anchoredBy, blockNum, timestamp, verdict] = result;

    if (exists) {
      show('verify-success');
      hide('verify-fail');
      setText('v2-anchored-by', anchoredBy);
      setText('v2-block',       blockNum.toString());
      setText('v2-timestamp',   new Date(Number(timestamp) * 1000).toLocaleString());
      setText('v2-verdict',     verdict);
    } else {
      hide('verify-success');
      show('verify-fail');
    }

  } catch (err) {
    console.error('Verification error:', err);
    showToast('Blockchain query failed. Ensure MetaMask is on Sepolia network.', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Verify on Blockchain`;
  }
}

// Pre-fill the verify field from State
function prefillVerify() {
  if (State.auditHash) {
    $('verify-hash-input').value = State.auditHash;
  }
  showSection('verify');
}

// ─── TOAST NOTIFICATIONS ──────────────────────────────────────────────────────

function showToast(message, type = 'info') {
  const container = $('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span>
    <span>${message}</span>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.classList.add('toast-visible'), 10);
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Copy hash to clipboard
function copyHash() {
  if (!State.auditHash) return;
  navigator.clipboard.writeText(State.auditHash)
    .then(() => showToast('Hash copied to clipboard', 'success'))
    .catch(() => showToast('Copy failed', 'error'));
}

// ─── INIT ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Initialize landing page animations
  initLanding();

  // Show landing section by default
  showSection('landing');

  // Attach form submission
  const form = $('manifest-form');
  if (form) form.addEventListener('submit', submitManifest);

  // Populate dropdowns from risk matrix (optional — uses static defaults)
  fetch(`${CONFIG.API_BASE}/api/risk-matrix`)
    .then(r => r.json())
    .then(data => {
      // Could populate datalist suggestions from data
      console.log('Risk matrix loaded:', data);
    })
    .catch(() => console.warn('Backend offline — running in demo mode'));

  // MetaMask account change listener
  if (window.ethereum) {
    window.ethereum.on('accountsChanged', (accounts) => {
      if (accounts.length === 0) {
        State.signer = null;
        State.walletAddress = null;
        hide('wallet-connected-badge');
        show('wallet-connect-btn');
      }
    });
  }
});