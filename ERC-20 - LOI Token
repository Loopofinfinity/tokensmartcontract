// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract LoopOfInfinity is ReentrancyGuard {
    using SafeMath for uint256;

string public name = "Loop Of Infinity";
string public symbol = "LOI";
uint8 public decimals = 18;
uint256 public totalSupply = 45e9 * 1e18; // initial supply of 45 billion
uint256 public maxSupply = 50e9 * 1e18; // maximum supply of 50 billion
uint256 private constant LOCKUP_PERIOD = 86400; // 1 day in seconds
uint256 private _lastEmergencyStopTime;
uint256 private _lastReleaseTime;


mapping(address => uint256) private _balances; // mapping is used to store the balance of each user's tokens.
mapping(address => mapping(address => uint256)) private _allowances; // the allowances mapping is used to store the approved amount of tokens that another address is allowed to transfer on behalf of the owner. The 
mapping(address => uint256) private _lastDepositTime; // is used to store the timestamp of the last deposit made by a user, which is used to determine if tokens are still locked up during a withdrawal.
mapping(bytes32 => bool) public _auditTrail; /**
 * @dev The `AuditTrail` event is emitted every time a deposit or a withdrawal is made.
 * The `auditTrail` mapping can be used to keep track of all the audit trails.
 * Each audit trail contains a hash of the transaction data, including the type of transaction (deposit or withdrawal),
 * the user's address, the amount of tokens, and the timestamp.
 * This provides an immutable record of all the deposits and withdrawals made in the contract, which can be useful for
 * auditing purposes.
 */

// Anti-whale system: maximum transfer amount of 250 million tokens per transaction
uint256 private maxTxAmount = 250e6 * 1e18;
uint256 private maxTransferPeriod = 1 days; // the maximum time period for a user to transfer tokens

address private _owner;
bool private _paused;
bool private _emergencyStop;
bool private _releaseStopped;

event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
event Paused(address account);
event Unpaused(address account);
event AuditTrail(bytes32 indexed auditHash); 
event EmergencyStop();
event Release();

modifier onlyOwner() {
    require(msg.sender == _owner, "Caller is not the owner");
    _;
}

modifier whenNotPaused() {
    require(!_paused || msg.sender == _owner, "Contract is paused");
    _;
}

modifier whenNotPausedAndNotOwner() {
    require(!_paused || msg.sender != _owner, "Contract is paused");
    _;
}

  modifier whenNotStopped() {
        require(!_emergencyStop, "Contract is stopped");
        _;
    }

      modifier whenStopped() {
        require(_emergencyStop, "Contract is not stopped");
        _;
    }

    modifier whenReleaseStopped() {
        require(!_releaseStopped, "Release is already stopped");
        _;
    }

 constructor() {
        _owner = msg.sender;
        _balances[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

function _fallback() external payable {
    if (msg.value > 0) {
        // send back the ether
        (bool success,) = msg.sender.call{value: msg.value}("");
        require(success, "Failed to return ETH");
    }
    else {
        revert("Invalid transaction");
    }
}

function pause() external onlyOwner {
    require(!_paused, "Contract is already paused");
    _paused = true;
    emit Paused(msg.sender);
}

function unpause() external onlyOwner {
    require(_paused, "Contract is not paused");
    _paused = false;
    emit Unpaused(msg.sender);
}

  function emergencyStop() external onlyOwner whenNotStopped {
    require(!_emergencyStop, "Contract is already stopped");
    require(block.timestamp >= _lastEmergencyStopTime + LOCKUP_PERIOD, "Cannot stop contract again yet");

    _emergencyStop = true;
    _lastEmergencyStopTime = block.timestamp;
    emit EmergencyStop();
}

 function release() external onlyOwner whenNotPaused whenNotStopped {
    require(!_emergencyStop, "Contract is stopped");
    require(!_releaseStopped, "Release is already stopped");
    require(block.timestamp >= _lastReleaseTime + LOCKUP_PERIOD, "Cannot release tokens yet");

    _releaseStopped = true;
    emit Release();

    // Update the last release time
    _lastReleaseTime = block.timestamp;
}

  function resume() external onlyOwner whenNotPaused whenStopped whenReleaseStopped {
    require(!_emergencyStop, "Contract is in an emergency stop"); // additional check
    _emergencyStop = false;
    _releaseStopped = false;
    emit Release();
}

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    // function to allow users to deposit tokens into the contract
function deposit(uint256 amount) external nonReentrant returns (bool) {
    require(amount > 0, "Deposit amount must be greater than zero"); 

    // Transfer tokens from the sender to the contract
    _transfer(msg.sender, address(this), amount);

    // Update last deposit timestamp for the user
    _lastDepositTime[msg.sender] = block.timestamp;

    // Add to audit trail
    bytes32 auditHash = keccak256(abi.encodePacked("deposit", msg.sender, amount, block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);

    return true;
}

// allow user to withdraw tokens 
function withdraw(uint256 amount) external nonReentrant whenNotStopped returns (bool) {
    require(amount > 0, "Withdrawal amount must be greater than zero");
    require(!_emergencyStop && !_releaseStopped, "Contract is stopped");
    require(_balances[msg.sender] >= amount, "Insufficient balance");

    // Check if the user's tokens are still locked up
    require(block.timestamp >= _lastDepositTime[msg.sender] + LOCKUP_PERIOD, "Tokens are still locked up");

    // Transfer tokens from the contract to the sender
    _transfer(address(this), msg.sender, amount);

    // Update last deposit time
    _lastDepositTime[msg.sender] = block.timestamp;

    // Emit audit trail event
    bytes32 auditHash = keccak256(abi.encodePacked("withdraw", msg.sender, amount, block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);

    return true;
}

    // function to allow the owner to withdraw tokens from the contract after a lockup period.
function withdrawByOwner(uint256 amount) external nonReentrant onlyOwner whenNotPausedAndNotOwner returns (bool) {
    require(amount > 0, "Withdraw amount must be greater than zero");

    // Check if tokens are still locked up
    require(block.timestamp >= _lastDepositTime[msg.sender] + LOCKUP_PERIOD, "Tokens are still locked up");

     // Check if user has enough tokens to withdraw
    require(amount <= _balances[msg.sender], "Insufficient balance");

    // Transfer tokens from the contract to the owner
    _transfer(address(this), msg.sender, amount);

    // Add to audit trail
    bytes32 auditHash = keccak256(abi.encodePacked("withdraw", msg.sender, amount, block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);

    return true;
}

function isContract(address account) internal view returns (bool) {
    uint256 codeSize;
    assembly {
        codeSize := extcodesize(account)
    }
    return codeSize > 0;
}

    // function to allow users to transfer tokens to other users.
    function transfer(address recipient, uint256 amount) external nonReentrant whenNotPaused returns (bool) {
    require(recipient != address(0), "Transfer to zero address");
    require(amount > 0, "Transfer amount must be greater than zero");
    require(amount <= _balances[msg.sender], "Insufficient balance");
    require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount");


    // Check if tokens are still locked up
    require(block.timestamp >= _lastDepositTime[msg.sender] + LOCKUP_PERIOD, "Tokens are still locked up");

    // Check if recipient is not a contract
    require(!isContract(recipient), "Recipient cannot be a contract");

    if (msg.sender != _owner && recipient != _owner) {
        require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount");

        // Check if the user has exceeded the maxTransferPeriod
        require(block.timestamp - _lastDepositTime[msg.sender] <= maxTransferPeriod, "Transfer period has exceeded the maximum allowed time.");
    }

    // Calculate tax
    uint256 taxAmount = amount.mul(2).div(100);

    // Transfer tokens from the sender to the contract, minus tax
    _transfer(msg.sender, address(this), amount.sub(taxAmount));
    
    // Update last deposit timestamp for the user
    _lastDepositTime[msg.sender] = block.timestamp;

    // Transfer tax to the owner
    _transfer(msg.sender, _owner, taxAmount);

    // Transfer remaining tokens from the contract to the recipient
    _transfer(address(this), recipient, amount.sub(taxAmount));

    // Add to audit trail
    bytes32 auditHash = keccak256(abi.encodePacked("transfer", msg.sender, recipient, amount, block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);

    return true;
}

function _transfer(address sender, address recipient, uint256 amount) internal whenNotPausedAndNotOwner whenNotStopped nonReentrant {
    require(sender != address(0), "Transfer from the zero address");
    require(recipient != address(0), "Transfer to the zero address");
    require(amount > 0, "Transfer amount must be greater than zero");

    // Check if total supply will exceed maximum supply
    require(totalSupply.add(amount) <= maxSupply, "Maximum supply exceeded");

    // Subtract the transferred amount from the sender's balance
    _balances[sender] = _balances[sender].sub(amount);

    // Add the transferred amount to the recipient's balance
    _balances[recipient] = _balances[recipient].add(amount);

    // Update total supply
    totalSupply = totalSupply.sub(amount);

    emit Transfer(sender, recipient, amount);
}

function _approve(address owner, address spender, uint256 amount) internal {
require(owner != address(0), "approve from the zero address");
require(spender != address(0), "approve to the zero address");
require(amount <= _balances[owner], "Insufficient balance to approve allowance");

uint256 currentAllowance = _allowances[owner][spender];
require(amount > currentAllowance, "Allowance is already greater than or equal to requested amount");

_allowances[owner][spender] = amount;
emit Approval(owner, spender, amount);
}

    function transferFrom(address sender, address recipient, uint256 amount) external nonReentrant whenNotPaused returns (bool) {
    require(sender != address(0), "Transfer from zero address");
    require(recipient != address(0), "Transfer to zero address");
    require(amount > 0, "Transfer amount must be greater than zero");
    require(amount <= _balances[sender], "Insufficient balance");
    require(amount <= _allowances[sender][msg.sender], "Insufficient allowance");

    // Check if sender and recipient are not contracts
    require(!isContract(sender), "Sender cannot be a contract");
    require(!isContract(recipient), "Recipient cannot be a contract");

    if (sender != _owner && recipient != _owner) {
        require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount");
    }

    // Calculate tax
    uint256 taxAmount = amount.mul(2).div(100);

    // Transfer tokens from the sender to the contract, minus tax
    _transfer(sender, address(this), amount.sub(taxAmount));

    // Update last deposit timestamp for the user
    _lastDepositTime[sender] = block.timestamp;

    // Transfer tax to the owner
    _transfer(sender, _owner, taxAmount);

    // Transfer remaining tokens from the contract to the recipient
    _transfer(address(this), recipient, amount.sub(taxAmount));

    // Decrease allowance
    _approve(msg.sender, sender, _allowances[sender][msg.sender].sub(amount));

    return true;
}

function getLastDepositTimestamp(address account) external view returns (uint256) {
    return _lastDepositTime[account];
}

function getRemainingTimeToWithdraw() external view returns (uint256) {
    uint256 lastDepositTime = _lastDepositTime[msg.sender];
    if (lastDepositTime == 0) {
        return 0;
    }
    uint256 remainingTime = lastDepositTime + LOCKUP_PERIOD - block.timestamp;
    if (remainingTime < 0) {
        return 0;
    }
    return remainingTime;
}


function increaseAllowance(address spender, uint256 addedValue) external nonReentrant returns (bool) {
    require(spender != address(0), "Increase allowance to zero address");
    _allowances[msg.sender][spender] = _allowances[msg.sender][spender].add(addedValue);
    emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
    return true;
}

function decreaseAllowance(address spender, uint256 subtractedValue) external nonReentrant returns (bool) {
    require(spender != address(0), "Decrease allowance to zero address");
    uint256 oldAllowance = _allowances[msg.sender][spender];
    if (subtractedValue >= oldAllowance) {
        _allowances[msg.sender][spender] = 0;
    } else {
        _allowances[msg.sender][spender] = oldAllowance.sub(subtractedValue);
    }
    emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
    return true;
}

function setMaxTxAmount(uint256 amount) external onlyOwner {
    require(amount > 0, "Amount must be greater than zero");
    require(amount <= totalSupply, "MaxTxAmount exceeds total supply");
    maxTxAmount = amount;
}

function renounceOwnership() external onlyOwner {
    emit OwnershipTransferred(_owner, address(0));
    _owner = address(0);
}

function transferOwnership(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Transfer to zero address");
    emit OwnershipTransferred(_owner, newOwner);
    _owner = newOwner;
}

function emergencyWithdraw() external onlyOwner {
    // Transfer all tokens from the contract to the owner
    _transfer(address(this), msg.sender, _balances[address(this)]);

    // Add to audit trail
    bytes32 auditHash = keccak256(abi.encodePacked("emergencyWithdraw", msg.sender, _balances[address(this)], block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);
}

function isExcludedFromReward(address account) external pure returns (bool) {
    return account == address(0);
}

function isExcludedFromFee(address account) external pure returns (bool) {
    return account == address(0);
}

event Transfer(address indexed from, address indexed to, uint256 amount);
event Approval(address indexed owner, address indexed spender, uint256 amount);
}
